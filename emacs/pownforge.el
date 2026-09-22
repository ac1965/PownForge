;;; pownforge.el --- Emacs front-end for the pownforge security CLI -*- lexical-binding: t; -*-

;; Keywords: tools, processes
;; Package-Requires: ((emacs "27.1"))

;;; Commentary:

;; A thin Emacs wrapper around the `pownforge' CLI (see README.md and
;; docs/handbook.md in the pownforge repository).  Every command here
;; shells out to the real `pownforge' binary and never re-implements scope
;; enforcement, plugin execution, or evidence handling itself: scope checks
;; and command execution stay in ScopePolicy/ScanRunner (Python side), same
;; as the CLI and the web UI both already do.
;;
;; Entry points:
;;   `pownforge-target-list', `pownforge-plugin-list' -- tabulated-list
;;     browsers for registered targets / available plugins.
;;   `pownforge-scan' -- pick a target and plugin, run
;;     `pownforge scan ... --live', and tail its output live in a buffer as
;;     it runs (the same line-by-line streaming the web UI's WebSocket view
;;     uses, here over a subprocess pipe instead).
;;   `pownforge-playbook-list', `pownforge-playbook-show' -- browse
;;     available playbooks (config/playbooks/*.yaml) and their steps.
;;   `pownforge-playbook-run' -- pick a playbook and a target, run
;;     `pownforge playbook run ...', and tail its per-step progress live in
;;     a buffer the same way `pownforge-scan' does.
;;   `pownforge-result-list', `pownforge-result-show' -- browse past runs;
;;     `result-show' renders findings with `pownforge-review-finding-at-point'
;;     bound locally to update a finding's review status in place.
;;   `pownforge-report-generate' -- generate and open a run's Markdown report.
;;   `pownforge-walkthrough-generate' -- generate a narrative walkthrough
;;     spanning several runs (or every run against a target), via the local
;;     LLM. Read-only: never touches a run's stored findings/analysis.
;;   `pownforge-audit-list' -- browse rejected scan attempts (ScopePolicy
;;     denials).
;;   `pownforge-findings-to-org' -- insert a run's findings as an Org
;;     outline at point (severity -> priority, status -> TODO state), with
;;     `pownforge-review-finding-in-org-at-point' to review a finding
;;     directly from that Org heading.
;;
;; See docs/handbook.md §9 (Emacs連携) in the pownforge repository for setup
;; and a full walkthrough.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'let-alist)
(require 'subr-x)
(require 'tabulated-list)

(defgroup pownforge nil
  "Emacs front-end for the pownforge security assessment CLI."
  :group 'tools
  :prefix "pownforge-")

(defcustom pownforge-executable "pownforge"
  "Path to the `pownforge' executable."
  :type 'string
  :group 'pownforge)

(defcustom pownforge-config-file nil
  "Value passed as `--config' to pownforge invocations that accept it.
When nil, pownforge's own default (config/targets.yaml relative to its
working directory) is used instead."
  :type '(choice (const :tag "Use pownforge's default" nil) file)
  :group 'pownforge)

(defcustom pownforge-workdir nil
  "Value passed as `--workdir' to pownforge invocations that accept it.
When nil, pownforge's own default (.pownforge/) is used instead."
  :type '(choice (const :tag "Use pownforge's default" nil) directory)
  :group 'pownforge)

;;; Low-level process helpers

(defun pownforge--global-args (accepts)
  "Return the --config/--workdir args allowed by ACCEPTS.
ACCEPTS is a list that may contain `:config' and/or `:workdir', matching
exactly which global options the target subcommand accepts (see
docs/handbook.md §5 CLIコマンドリファレンス: `plugin list'/`plugin info'/
`lab list' accept neither)."
  (append
   (when (and (memq :config accepts) pownforge-config-file)
     (list "--config" (expand-file-name pownforge-config-file)))
   (when (and (memq :workdir accepts) pownforge-workdir)
     (list "--workdir" (expand-file-name pownforge-workdir)))))

(defun pownforge--run-to-string (args)
  "Run pownforge with ARGS synchronously and return its stdout as a string.
Signals a `user-error' with pownforge's stderr text if it exits non-zero."
  (let ((err-file (make-temp-file "pownforge-err")))
    (unwind-protect
        (with-temp-buffer
          (let ((status (apply #'call-process pownforge-executable nil
                                (list t err-file) nil args)))
            (if (eq status 0)
                (buffer-string)
              (user-error "pownforge %s failed: %s"
                          (string-join args " ")
                          (string-trim
                           (with-temp-buffer
                             (insert-file-contents err-file)
                             (buffer-string)))))))
      (delete-file err-file))))

(defun pownforge--run (subcommand-args accepts)
  "Run pownforge with SUBCOMMAND-ARGS plus the global args allowed by ACCEPTS."
  (pownforge--run-to-string (append subcommand-args (pownforge--global-args accepts))))

;;; Output parsers (pure functions, unit-tested independently of any process)

(defun pownforge-parse-target-list (output)
  "Parse `pownforge target list' textual OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :name (nth 0 fields)
                           :kind (nth 1 fields)
                           :address (nth 2 fields)
                           :plugins (string-remove-prefix "plugins=" (nth 3 fields))
                           :type (string-remove-prefix "type=" (nth 4 fields))
                           :environment (string-remove-prefix "env=" (nth 5 fields))))))

(defun pownforge-parse-plugin-list (output)
  "Parse `pownforge plugin list' textual OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :name (nth 0 fields)
                           :version (string-remove-prefix "v" (nth 1 fields))
                           :status (nth 2 fields)
                           :description (nth 3 fields)))))

(defun pownforge-parse-result-list (output)
  "Parse `pownforge result list' textual OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :run-id (nth 0 fields)
                           :created-at (nth 1 fields)
                           :target (nth 2 fields)
                           :plugin (nth 3 fields)))))

(defun pownforge-parse-audit-list (output)
  "Parse `pownforge audit list' textual OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :violation-id (nth 0 fields)
                           :occurred-at (nth 1 fields)
                           :target (nth 2 fields)
                           :plugin (nth 3 fields)
                           :reason (nth 4 fields)))))

(defun pownforge-parse-run-id (output)
  "Extract the run id from `pownforge scan ...' OUTPUT, or nil if absent.
Works whether or not OUTPUT also contains `--live' tool-output lines, since
Emacs regexps match `^'/`$' per line rather than only at the string ends."
  (when (string-match "^run \\([a-zA-Z0-9]+\\) completed" output)
    (match-string 1 output)))

(defun pownforge--parse-run-json (json-string)
  "Parse JSON-STRING (a `result show'/`audit show' body) into nested alists."
  (json-parse-string json-string :object-type 'alist :array-type 'list
                      :null-object nil :false-object nil))

(defun pownforge--severity-rank (severity)
  "Sort key for SEVERITY, highest severity first."
  (pcase severity
    ("critical" 4) ("high" 3) ("medium" 2) ("low" 1) (_ 0)))

;;; Org-mode mapping helpers

(defun pownforge-severity-priority (severity)
  "Map a pownforge SEVERITY string to an Org priority character."
  (pcase severity
    ((or "critical" "high") ?A)
    ("medium" ?B)
    (_ ?C)))

(defun pownforge-status-to-todo (status)
  "Map a pownforge finding STATUS string to an Org TODO keyword."
  (pcase status
    ("confirmed" "DONE")
    ("false-positive" "CANCELLED")
    (_ "TODO")))

;;; Targets

(defvar pownforge-target-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map "s" #'pownforge-scan)
    map)
  "Keymap for `pownforge-target-list-mode'.")

(define-derived-mode pownforge-target-list-mode tabulated-list-mode "PownForge-Targets"
  "Major mode listing pownforge registered targets.
\\{pownforge-target-list-mode-map}"
  (setq tabulated-list-format
        [("Name" 16 t) ("Kind" 6 t) ("Address" 24 t)
         ("Type" 10 t) ("Env" 10 t) ("Plugins" 20 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--target-list-entries)
  (tabulated-list-init-header))

(defun pownforge--target-list-entries ()
  (mapcar (lambda (target)
            (list (plist-get target :name)
                  (vector (plist-get target :name)
                          (plist-get target :kind)
                          (plist-get target :address)
                          (plist-get target :type)
                          (plist-get target :environment)
                          (plist-get target :plugins))))
          (pownforge-parse-target-list (pownforge--run '("target" "list") '(:config)))))

;;;###autoload
(defun pownforge-target-list ()
  "Show registered pownforge targets in a tabulated-list buffer.
Press `s' on a row to start a scan against that target."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-targets*")))
    (with-current-buffer buf
      (pownforge-target-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

;;; Plugins

(defvar pownforge-plugin-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    map)
  "Keymap for `pownforge-plugin-list-mode'.")

(define-derived-mode pownforge-plugin-list-mode tabulated-list-mode "PownForge-Plugins"
  "Major mode listing available pownforge plugins."
  (setq tabulated-list-format
        [("Name" 14 t) ("Version" 10 t) ("Status" 24 t) ("Description" 50 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--plugin-list-entries)
  (tabulated-list-init-header))

(defun pownforge--plugin-list-entries ()
  (mapcar (lambda (plugin)
            (list (plist-get plugin :name)
                  (vector (plist-get plugin :name)
                          (plist-get plugin :version)
                          (plist-get plugin :status)
                          (plist-get plugin :description))))
          (pownforge-parse-plugin-list (pownforge--run '("plugin" "list") '()))))

;;;###autoload
(defun pownforge-plugin-list ()
  "Show available pownforge plugins in a tabulated-list buffer."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-plugins*")))
    (with-current-buffer buf
      (pownforge-plugin-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

;;; Scan (live output)

(defvar-local pownforge--scan-run-id nil
  "Run id parsed from the current `pownforge-scan-mode' buffer, once known.")

(defvar pownforge-scan-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "C-c C-c") #'pownforge-scan-open-result)
    map)
  "Keymap for `pownforge-scan-mode'.")

(define-derived-mode pownforge-scan-mode special-mode "PownForge-Scan"
  "Major mode for a live pownforge scan output buffer.
\\{pownforge-scan-mode-map}")

(defun pownforge-scan-open-result ()
  "Open the result of the scan running in the current buffer."
  (interactive)
  (unless pownforge--scan-run-id
    (user-error "No run id yet (the scan may still be running, or failed)"))
  (pownforge-result-show pownforge--scan-run-id))

(defun pownforge--scan-filter (proc string)
  "Process filter appending STRING to PROC's buffer, tailing style."
  (when (buffer-live-p (process-buffer proc))
    (with-current-buffer (process-buffer proc)
      (let ((inhibit-read-only t)
            (moving (= (point) (process-mark proc))))
        (save-excursion
          (goto-char (process-mark proc))
          (insert string)
          (set-marker (process-mark proc) (point)))
        (when moving (goto-char (process-mark proc)))))))

(defun pownforge--scan-sentinel (proc _event)
  "Process sentinel that resolves the run id once PROC exits.
`process-status' returns a symbol (e.g. `exit'), not a string, so the
no-run-id branch formats it directly rather than passing it through
`string-trim' (which signals wrong-type-argument on a symbol)."
  (when (memq (process-status proc) '(exit signal))
    (when (buffer-live-p (process-buffer proc))
      (with-current-buffer (process-buffer proc)
        (let ((inhibit-read-only t)
              (run-id (pownforge-parse-run-id (buffer-string))))
          (goto-char (point-max))
          (if run-id
              (progn
                (setq pownforge--scan-run-id run-id)
                (insert (format "\n[done] run %s (C-c C-c to open the result)\n" run-id)))
            (insert (format "\n[%s]\n" (process-status proc)))))))))

;;;###autoload
(defun pownforge-scan (target plugin options)
  "Run `pownforge scan' for TARGET/PLUGIN with OPTIONS, live-tailing output.
OPTIONS is a string of space-separated key=value pairs, e.g.
\"ports=22,80 timing=4\" (empty string for no options).  Interactively,
TARGET and PLUGIN are read via `completing-read', with the plugin choices
narrowed to that target's `allowed_plugins' when it has any."
  (interactive
   (let* ((targets (pownforge-parse-target-list (pownforge--run '("target" "list") '(:config))))
          (target (completing-read "Target: "
                                    (mapcar (lambda (r) (plist-get r :name)) targets) nil t))
          (allowed (plist-get
                    (cl-find target targets :key (lambda (r) (plist-get r :name)) :test #'equal)
                    :plugins))
          (plugin-choices (if (and allowed (not (member allowed '("" "any"))))
                               (split-string allowed ", " t)
                             (mapcar (lambda (p) (plist-get p :name))
                                     (pownforge-parse-plugin-list
                                      (pownforge--run '("plugin" "list") '())))))
          (plugin (completing-read "Plugin: " plugin-choices nil t))
          (options (read-string "Options (key=value, space separated, blank for none): ")))
     (list target plugin options)))
  (let* ((option-args (cl-loop for kv in (split-string options " " t)
                               append (list "--option" kv)))
         (args (append (list "scan" plugin "--target" target "--live") option-args
                        (pownforge--global-args '(:config :workdir))))
         (buf (generate-new-buffer (format "*pownforge-scan: %s/%s*" target plugin))))
    (with-current-buffer buf
      (pownforge-scan-mode)
      (setq pownforge--scan-run-id nil)
      (let ((inhibit-read-only t))
        (insert (format "$ %s %s\n\n" pownforge-executable (string-join args " ")))))
    (let ((proc (apply #'start-process (format "pownforge-scan-%s" target) buf
                        pownforge-executable args)))
      (set-marker (process-mark proc) (with-current-buffer buf (point-max)))
      (set-process-filter proc #'pownforge--scan-filter)
      (set-process-sentinel proc #'pownforge--scan-sentinel))
    (pop-to-buffer buf)))

;;; Playbooks

(defun pownforge-parse-playbook-list (output)
  "Parse `pownforge playbook list' textual OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :name (nth 0 fields)
                           :steps (nth 1 fields)
                           :description (nth 2 fields)))))

(defun pownforge-parse-playbook-run-ids (output)
  "Extract every step run id from `pownforge playbook run ...' OUTPUT, in order.
Matches each step's \"run <id> completed\" line (see cli.py's `playbook run'
output), unlike `pownforge-parse-run-id' which only matches a line that
*starts* with \"run \" (a plain `scan''s output)."
  (let (ids (start 0))
    (while (string-match "run \\([a-zA-Z0-9]+\\) completed" output start)
      (push (match-string 1 output) ids)
      (setq start (match-end 0)))
    (nreverse ids)))

(defvar pownforge-playbook-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map (kbd "RET") #'pownforge-playbook-list-show)
    (define-key map "r" #'pownforge-playbook-run)
    map)
  "Keymap for `pownforge-playbook-list-mode'.")

(define-derived-mode pownforge-playbook-list-mode tabulated-list-mode "PownForge-Playbooks"
  "Major mode listing available pownforge playbooks.
\\{pownforge-playbook-list-mode-map}"
  (setq tabulated-list-format
        [("Name" 20 t) ("Steps" 8 t) ("Description" 50 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--playbook-list-entries)
  (tabulated-list-init-header))

(defun pownforge--playbook-list-entries ()
  (mapcar (lambda (p)
            (list (plist-get p :name)
                  (vector (plist-get p :name) (plist-get p :steps) (plist-get p :description))))
          (pownforge-parse-playbook-list (pownforge--run '("playbook" "list") '()))))

;;;###autoload
(defun pownforge-playbook-list ()
  "Show available pownforge playbooks in a tabulated-list buffer.
Press RET on a row to view that playbook's steps, `r' to run it against a
target."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-playbooks*")))
    (with-current-buffer buf
      (pownforge-playbook-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

(defun pownforge-playbook-list-show ()
  "Show the playbook at point's steps."
  (interactive)
  (let ((name (tabulated-list-get-id)))
    (unless name (user-error "No playbook on this line"))
    (pownforge-playbook-show name)))

;;;###autoload
(defun pownforge-playbook-show (name)
  "Show playbook NAME's steps (`pownforge playbook show NAME')."
  (interactive
   (list (completing-read "Playbook: "
                           (mapcar (lambda (p) (plist-get p :name))
                                   (pownforge-parse-playbook-list
                                    (pownforge--run '("playbook" "list") '())))
                           nil t)))
  (let ((output (pownforge--run (list "playbook" "show" name) '())))
    (with-current-buffer (get-buffer-create (format "*pownforge-playbook: %s*" name))
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert output))
      (special-mode)
      (pop-to-buffer (current-buffer)))))

;;; Playbook run (live output)

(defvar pownforge-playbook-run-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "C-c C-c") #'pownforge-playbook-run-open-result)
    map)
  "Keymap for `pownforge-playbook-run-mode'.")

(define-derived-mode pownforge-playbook-run-mode special-mode "PownForge-Playbook-Run"
  "Major mode for a live pownforge playbook run output buffer.
\\{pownforge-playbook-run-mode-map}")

(defun pownforge-playbook-run-open-result ()
  "Open one of this playbook run's step results.
Prompts to pick one when the playbook produced more than one run."
  (interactive)
  (let ((ids (pownforge-parse-playbook-run-ids (buffer-string))))
    (unless ids (user-error "No completed step run ids yet"))
    (pownforge-result-show
     (if (= (length ids) 1) (car ids) (completing-read "Run id: " ids nil t)))))

(defun pownforge--playbook-run-filter (proc string)
  "Process filter appending STRING to PROC's buffer, tailing style."
  (when (buffer-live-p (process-buffer proc))
    (with-current-buffer (process-buffer proc)
      (let ((inhibit-read-only t)
            (moving (= (point) (process-mark proc))))
        (save-excursion
          (goto-char (process-mark proc))
          (insert string)
          (set-marker (process-mark proc) (point)))
        (when moving (goto-char (process-mark proc)))))))

(defun pownforge--playbook-run-sentinel (proc _event)
  "Process sentinel that annotates the buffer once PROC exits.
`process-status' returns a symbol (e.g. `exit'), not a string, so this
formats it directly rather than passing it through `string-trim'."
  (when (memq (process-status proc) '(exit signal))
    (when (buffer-live-p (process-buffer proc))
      (with-current-buffer (process-buffer proc)
        (let ((inhibit-read-only t))
          (goto-char (point-max))
          (insert (format "\n[%s] (C-c C-c to open a step's result)\n"
                          (process-status proc))))))))

;;;###autoload
(defun pownforge-playbook-run (name target)
  "Run playbook NAME against TARGET, live-tailing output.
Interactively, NAME and TARGET are read via `completing-read'."
  (interactive
   (list (completing-read "Playbook: "
                           (mapcar (lambda (p) (plist-get p :name))
                                   (pownforge-parse-playbook-list
                                    (pownforge--run '("playbook" "list") '())))
                           nil t)
         (completing-read "Target: "
                           (mapcar (lambda (r) (plist-get r :name))
                                   (pownforge-parse-target-list
                                    (pownforge--run '("target" "list") '(:config))))
                           nil t)))
  (let* ((args (append (list "playbook" "run" name "--target" target)
                        (pownforge--global-args '(:config :workdir))))
         (buf (generate-new-buffer (format "*pownforge-playbook-run: %s/%s*" name target))))
    (with-current-buffer buf
      (pownforge-playbook-run-mode)
      (let ((inhibit-read-only t))
        (insert (format "$ %s %s\n\n" pownforge-executable (string-join args " ")))))
    (let ((proc (apply #'start-process (format "pownforge-playbook-run-%s" name) buf
                        pownforge-executable args)))
      (set-marker (process-mark proc) (with-current-buffer buf (point-max)))
      (set-process-filter proc #'pownforge--playbook-run-filter)
      (set-process-sentinel proc #'pownforge--playbook-run-sentinel))
    (pop-to-buffer buf)))

;;; Results (list + detail)

(defvar pownforge-result-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map (kbd "RET") #'pownforge-result-list-show)
    (define-key map "o" #'pownforge-result-list-to-org)
    map)
  "Keymap for `pownforge-result-list-mode'.")

(define-derived-mode pownforge-result-list-mode tabulated-list-mode "PownForge-Runs"
  "Major mode listing past pownforge scan runs.
\\{pownforge-result-list-mode-map}"
  (setq tabulated-list-format
        [("Run" 14 t) ("Created" 20 t) ("Target" 14 t) ("Plugin" 10 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--result-list-entries)
  (tabulated-list-init-header))

(defun pownforge--result-list-entries ()
  (mapcar (lambda (r)
            (list (plist-get r :run-id)
                  (vector (plist-get r :run-id) (plist-get r :created-at)
                          (plist-get r :target) (plist-get r :plugin))))
          (pownforge-parse-result-list (pownforge--run '("result" "list") '(:workdir)))))

(defun pownforge-result-list-show ()
  "Show the full record for the run at point."
  (interactive)
  (pownforge-result-show (tabulated-list-get-id)))

(defun pownforge-result-list-to-org ()
  "Insert the findings for the run at point as Org, into the next Org buffer."
  (interactive)
  (let ((run-id (tabulated-list-get-id))
        (target-buffer (read-buffer "Insert into org buffer: " nil t
                                     (lambda (b) (with-current-buffer (if (consp b) (cdr b) b)
                                                   (derived-mode-p 'org-mode))))))
    (pop-to-buffer target-buffer)
    (pownforge-findings-to-org run-id)))

;;;###autoload
(defun pownforge-result-list ()
  "Show past pownforge scan runs in a tabulated-list buffer.
Press RET on a row for the full record, `o' to insert its findings as Org."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-runs*")))
    (with-current-buffer buf
      (pownforge-result-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

(defvar pownforge-result-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map "r" #'pownforge-review-finding-at-point)
    (define-key map "g" #'pownforge-result-refresh)
    map)
  "Keymap for `pownforge-result-mode'.")

(define-derived-mode pownforge-result-mode special-mode "PownForge-Result"
  "Major mode for viewing a single pownforge run record.
\\{pownforge-result-mode-map}")

(defvar-local pownforge--result-run-id nil
  "Run id shown in the current `pownforge-result-mode' buffer.")

(defun pownforge-result-refresh ()
  "Reload the run record shown in the current buffer."
  (interactive)
  (pownforge-result-show pownforge--result-run-id))

;;;###autoload
(defun pownforge-result-show (run-id)
  "Show the full record for RUN-ID in a readable buffer.
Findings are listed severity-first; press `r' on one to review it
(set needs-review/confirmed/false-positive) via `pownforge result review'."
  (interactive
   (list (completing-read "Run id: "
                           (mapcar (lambda (r) (plist-get r :run-id))
                                   (pownforge-parse-result-list
                                    (pownforge--run '("result" "list") '(:workdir))))
                           nil t)))
  (let* ((record (pownforge--parse-run-json
                   (pownforge--run (list "result" "show" run-id) '(:workdir))))
         (buf (get-buffer-create (format "*pownforge-run: %s*" run-id))))
    (with-current-buffer buf
      (pownforge-result-mode)
      (setq pownforge--result-run-id run-id)
      (let ((inhibit-read-only t))
        (erase-buffer)
        (pownforge--render-run record))
      (goto-char (point-min)))
    (pop-to-buffer buf)))

(defun pownforge--render-run (record)
  "Insert a human-readable rendering of RUN's parsed JSON into the current buffer."
  (let-alist record
    (insert (format "Run:      %s\n" .run_id))
    (insert (format "Target:   %s\n" .target))
    (insert (format "Plugin:   %s\n" .plugin))
    (insert (format "Created:  %s\n" .created_at))
    (insert (format "Exit:     %s\n" (alist-get 'returncode .evidence)))
    (insert (format "Tool ver: %s\n" (or (alist-get 'tool_version .evidence) "-")))
    (insert "\n")
    (if (null .findings)
        (insert "(no findings)\n")
      (insert "Findings (press `r' on a line to review it):\n\n")
      (dolist (f (sort (copy-sequence .findings)
                        (lambda (a b) (> (pownforge--severity-rank (alist-get 'severity a))
                                          (pownforge--severity-rank (alist-get 'severity b))))))
        (let* ((finding-id (alist-get 'finding_id f))
               (title (alist-get 'title f))
               (severity (alist-get 'severity f))
               (status (alist-get 'status f))
               (source (alist-get 'source f))
               (detail (alist-get 'detail f))
               (start (point)))
          (insert (format "[%-8s][%-14s][%s] %s\n" severity status source title))
          (unless (string-empty-p (or detail ""))
            (insert (format "    %s\n" detail)))
          (put-text-property start (point) 'pownforge-run-id .run_id)
          (put-text-property start (point) 'pownforge-finding-id finding-id)
          (insert "\n"))))
    (when .analysis
      (insert (format "\nAI analysis (source=\"ai\", unverified until reviewed):\n%s\n" .analysis)))))

(defun pownforge-review-finding-at-point ()
  "Review the finding at point in a `pownforge-result-mode' buffer."
  (interactive)
  (let ((run-id (get-text-property (point) 'pownforge-run-id))
        (finding-id (get-text-property (point) 'pownforge-finding-id)))
    (unless (and run-id finding-id)
      (user-error "No finding at point"))
    (let ((status (completing-read (format "New status for %s: " finding-id)
                                    '("needs-review" "confirmed" "false-positive") nil t)))
      (message "%s" (pownforge--run (list "result" "review" run-id finding-id status) '(:workdir)))
      (pownforge-result-show run-id))))

;;; Reports

;;;###autoload
(defun pownforge-report-generate (run-id)
  "Generate RUN-ID's Markdown report and open it."
  (interactive
   (list (completing-read "Run id: "
                           (mapcar (lambda (r) (plist-get r :run-id))
                                   (pownforge-parse-result-list
                                    (pownforge--run '("result" "list") '(:workdir))))
                           nil t)))
  (let* ((out (pownforge--run (list "report" "generate" run-id) '(:workdir)))
         (path (when (string-match "wrote \\(.+\\)$" out) (match-string 1 out))))
    (unless path
      (user-error "could not determine report path from: %s" out))
    (find-file (string-trim path))))

;;;###autoload
(defun pownforge-walkthrough-generate ()
  "Generate a narrative walkthrough spanning multiple runs and open it.
Prompts repeatedly for run ids to include, in that order (blank to stop);
if none are given, prompts for a target instead (every run recorded
against it, oldest first). Read-only: unlike `pownforge-report-generate'
this never touches any run's stored findings/analysis -- see
`pownforge result review'/Org integration for that."
  (interactive)
  (let* ((run-choices (mapcar (lambda (r) (plist-get r :run-id))
                               (pownforge-parse-result-list
                                (pownforge--run '("result" "list") '(:workdir)))))
         (run-ids (cl-loop for id = (completing-read
                                     "Add run id (blank to finish): " run-choices)
                            while (not (string-empty-p id))
                            collect id))
         (target (when (null run-ids)
                   (completing-read
                    "Target (every run recorded against it, oldest first): "
                    (mapcar (lambda (r) (plist-get r :name))
                            (pownforge-parse-target-list
                             (pownforge--run '("target" "list") '(:config))))
                    nil t)))
         (chosen-format (completing-read "Format: " '("markdown" "html") nil t "markdown"))
         (args (append (list "walkthrough" "generate") run-ids
                        (when target (list "--target" target))
                        (list "--format" chosen-format)
                        (pownforge--global-args '(:workdir))))
         (out (pownforge--run-to-string args))
         (path (when (string-match "wrote \\(.+\\)$" out) (match-string 1 out))))
    (unless path
      (user-error "could not determine report path from: %s" out))
    (find-file (string-trim path))))

;;; Audit (rejected scan attempts)

(defvar pownforge-audit-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    map)
  "Keymap for `pownforge-audit-list-mode'.")

(define-derived-mode pownforge-audit-list-mode tabulated-list-mode "PownForge-Audit"
  "Major mode listing rejected pownforge scan attempts (ScopePolicy denials)."
  (setq tabulated-list-format
        [("Occurred" 20 t) ("Target" 14 t) ("Plugin" 10 t) ("Reason" 60 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--audit-list-entries)
  (tabulated-list-init-header))

(defun pownforge--audit-list-entries ()
  (mapcar (lambda (v)
            (list (plist-get v :violation-id)
                  (vector (plist-get v :occurred-at) (plist-get v :target)
                          (plist-get v :plugin) (plist-get v :reason))))
          (pownforge-parse-audit-list (pownforge--run '("audit" "list") '(:workdir)))))

;;;###autoload
(defun pownforge-audit-list ()
  "Show rejected pownforge scan attempts (ScopePolicy denials)."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-audit*")))
    (with-current-buffer buf
      (pownforge-audit-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

;;; Org-mode integration

;;;###autoload
(defun pownforge-findings-to-org (run-id)
  "Insert RUN-ID's findings as an Org outline at point.
Must be called with point in an `org-mode' buffer.  Each finding heading
carries POWNFORGE_RUN_ID/POWNFORGE_FINDING_ID properties so
`pownforge-review-finding-in-org-at-point' can later review it directly
from Org.  Severity maps to Org priority (critical/high -> A, medium -> B,
low/info -> C) and status maps to the TODO keyword (needs-review -> TODO,
confirmed -> DONE, false-positive -> CANCELLED); add CANCELLED to your
`org-todo-keywords' if you don't already track a cancelled/rejected state."
  (interactive
   (list (completing-read "Run id: "
                           (mapcar (lambda (r) (plist-get r :run-id))
                                   (pownforge-parse-result-list
                                    (pownforge--run '("result" "list") '(:workdir))))
                           nil t)))
  (unless (derived-mode-p 'org-mode)
    (user-error "pownforge-findings-to-org must be run in an org-mode buffer"))
  (let ((record (pownforge--parse-run-json
                 (pownforge--run (list "result" "show" run-id) '(:workdir)))))
    (let-alist record
      (insert (format "* Run %s: %s / %s\n" .run_id .target .plugin))
      (if (null .findings)
          (insert "  (no findings)\n")
        (dolist (f .findings)
          (let ((finding-id (alist-get 'finding_id f))
                (title (alist-get 'title f))
                (severity (alist-get 'severity f))
                (status (alist-get 'status f))
                (source (alist-get 'source f))
                (detail (alist-get 'detail f)))
            (insert (format "** %s [#%c] %s  :%s:%s:\n"
                             (pownforge-status-to-todo status)
                             (pownforge-severity-priority severity)
                             title severity source))
            (insert ":PROPERTIES:\n")
            (insert (format ":POWNFORGE_RUN_ID: %s\n" .run_id))
            (insert (format ":POWNFORGE_FINDING_ID: %s\n" finding-id))
            (insert ":END:\n")
            (unless (string-empty-p (or detail ""))
              (insert (format "%s\n" detail)))))))))

;;;###autoload
(defun pownforge-review-finding-in-org-at-point ()
  "Review the finding at the current Org heading, then update its TODO state.
Reads POWNFORGE_RUN_ID/POWNFORGE_FINDING_ID from the heading's properties
(as inserted by `pownforge-findings-to-org'), prompts for a new status,
calls `pownforge result review', and sets the heading's TODO keyword to
match."
  (interactive)
  (unless (derived-mode-p 'org-mode)
    (user-error "must be called from an org-mode buffer"))
  (require 'org)
  (let ((run-id (org-entry-get nil "POWNFORGE_RUN_ID"))
        (finding-id (org-entry-get nil "POWNFORGE_FINDING_ID")))
    (unless (and run-id finding-id)
      (user-error "No POWNFORGE_RUN_ID/POWNFORGE_FINDING_ID property at point"))
    (let ((status (completing-read (format "New status for %s: " finding-id)
                                    '("needs-review" "confirmed" "false-positive") nil t)))
      (message "%s" (pownforge--run (list "result" "review" run-id finding-id status) '(:workdir)))
      (org-todo (pownforge-status-to-todo status)))))

(provide 'pownforge)

;;; pownforge.el ends here
