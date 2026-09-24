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
;;   `pownforge-attack-session-list', `pownforge-attack-session-show' --
;;     browse named, human-curated paths of already-recorded runs.
;;   `pownforge-attack-session-create', `pownforge-attack-session-add-stage' --
;;     create a session and append an existing run id to it. Never executes
;;     anything: only records a reference to a run that already happened.
;;   `pownforge-attack-session-report' -- render a session's stages (in
;;     order) into a Markdown report and open it.
;;   `pownforge-operation-list', `pownforge-operation-show' -- browse
;;     AttackOperations (a planned graph of nodes/edges/candidate actions,
;;     distinct from AttackSession above -- see docs/handbook.md §14).
;;   `pownforge-operation-create', `pownforge-operation-add-node',
;;     `pownforge-operation-add-edge', `pownforge-operation-add-action' --
;;     build up an operation's graph and candidate actions. Never executes
;;     anything by itself.
;;   `pownforge-operation-approve' -- record human approval for a
;;     candidate action; required before it can be executed.
;;   `pownforge-operation-execute' -- execute an approved action. A SCAN
;;     action runs through the real ScanRunner; MANUAL/PIVOT actions never
;;     execute anything themselves, only record a transcript the operator
;;     already ran (same as `pownforge-result-import').
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

;;; Attack sessions (record/track already-recorded runs as a named path)

(defun pownforge-parse-attack-session-list (output)
  "Parse `pownforge attack-session list' textual OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :name (nth 0 fields)
                           :stages (nth 1 fields)
                           :description (nth 2 fields)))))

(defvar pownforge-attack-session-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map (kbd "RET") #'pownforge-attack-session-list-show)
    (define-key map "c" #'pownforge-attack-session-create)
    (define-key map "a" #'pownforge-attack-session-add-stage)
    map)
  "Keymap for `pownforge-attack-session-list-mode'.")

(define-derived-mode pownforge-attack-session-list-mode tabulated-list-mode "PownForge-AttackSessions"
  "Major mode listing pownforge attack sessions.
\\{pownforge-attack-session-list-mode-map}"
  (setq tabulated-list-format
        [("Name" 20 t) ("Stages" 10 t) ("Description" 50 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--attack-session-list-entries)
  (tabulated-list-init-header))

(defun pownforge--attack-session-list-entries ()
  (mapcar (lambda (s)
            (list (plist-get s :name)
                  (vector (plist-get s :name) (plist-get s :stages) (plist-get s :description))))
          (pownforge-parse-attack-session-list (pownforge--run '("attack-session" "list") '(:workdir)))))

;;;###autoload
(defun pownforge-attack-session-list ()
  "Show pownforge attack sessions in a tabulated-list buffer.
Press RET on a row to view that session's stages, `c' to create a new
session, `a' to append a stage to one."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-attack-sessions*")))
    (with-current-buffer buf
      (pownforge-attack-session-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

(defun pownforge-attack-session-list-show ()
  "Show the attack session at point's stages."
  (interactive)
  (let ((name (tabulated-list-get-id)))
    (unless name (user-error "No attack session on this line"))
    (pownforge-attack-session-show name)))

;;;###autoload
(defun pownforge-attack-session-show (name)
  "Show attack session NAME's stages (`pownforge attack-session show NAME')."
  (interactive
   (list (completing-read "Attack session: "
                           (mapcar (lambda (s) (plist-get s :name))
                                   (pownforge-parse-attack-session-list
                                    (pownforge--run '("attack-session" "list") '(:workdir))))
                           nil t)))
  (let ((output (pownforge--run (list "attack-session" "show" name) '(:workdir))))
    (with-current-buffer (get-buffer-create (format "*pownforge-attack-session: %s*" name))
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert output))
      (special-mode)
      (pop-to-buffer (current-buffer)))))

;;;###autoload
(defun pownforge-attack-session-create (name description engagement)
  "Create a new, empty attack session NAME with DESCRIPTION/ENGAGEMENT.
Never executes anything -- only registers a name that
`pownforge-attack-session-add-stage' can then append already-recorded runs
to."
  (interactive
   (list (read-string "New attack session name: ")
         (read-string "Description (blank for none): ")
         (read-string "Engagement (blank for none, cross-reference only): ")))
  (let ((args (append (list "attack-session" "create" name)
                       (unless (string-empty-p description) (list "--description" description))
                       (unless (string-empty-p engagement) (list "--engagement" engagement)))))
    (message "%s" (string-trim (pownforge--run args '(:workdir))))))

;;;###autoload
(defun pownforge-attack-session-add-stage (name run-id label)
  "Append RUN-ID (with optional LABEL) as the next stage of session NAME.
RUN-ID must already exist (from `pownforge-scan'/`pownforge-playbook-run'/
`pownforge result import') -- this never creates a run or executes
anything."
  (interactive
   (list (completing-read "Attack session: "
                           (mapcar (lambda (s) (plist-get s :name))
                                   (pownforge-parse-attack-session-list
                                    (pownforge--run '("attack-session" "list") '(:workdir))))
                           nil t)
         (completing-read "Run id: "
                           (mapcar (lambda (r) (plist-get r :run-id))
                                   (pownforge-parse-result-list
                                    (pownforge--run '("result" "list") '(:workdir))))
                           nil t)
         (read-string "Label (blank for none): ")))
  (let ((args (append (list "attack-session" "add-stage" name run-id)
                       (unless (string-empty-p label) (list "--label" label)))))
    (message "%s" (string-trim (pownforge--run args '(:workdir))))))

;;;###autoload
(defun pownforge-attack-session-report (name)
  "Generate attack session NAME's Markdown report and open it."
  (interactive
   (list (completing-read "Attack session: "
                           (mapcar (lambda (s) (plist-get s :name))
                                   (pownforge-parse-attack-session-list
                                    (pownforge--run '("attack-session" "list") '(:workdir))))
                           nil t)))
  (let* ((out (pownforge--run (list "attack-session" "report" name) '(:workdir)))
         (path (when (string-match "wrote \\(.+\\)$" out) (match-string 1 out))))
    (unless path
      (user-error "could not determine report path from: %s" out))
    (find-file (string-trim path))))

;;; Attack operations (plan a graph of nodes/edges/candidate actions and
;;; carry them through approval before execution -- distinct from Attack
;;; sessions above, which only record already-recorded runs as a named
;;; path; see docs/handbook.md §14)

(defun pownforge-parse-operation-list (output)
  "Parse `pownforge operation list' textual OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :name (nth 0 fields)
                           :nodes (nth 1 fields)
                           :actions (nth 2 fields)
                           :objective (nth 3 fields)))))

(defun pownforge--operation-names ()
  "Return every existing attack operation's name, for `completing-read'."
  (mapcar (lambda (op) (plist-get op :name))
          (pownforge-parse-operation-list (pownforge--run '("operation" "list") '(:workdir)))))

(defvar pownforge-operation-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map (kbd "RET") #'pownforge-operation-list-show)
    (define-key map "c" #'pownforge-operation-create)
    (define-key map "n" #'pownforge-operation-add-node)
    (define-key map "e" #'pownforge-operation-add-edge)
    (define-key map "a" #'pownforge-operation-add-action)
    (define-key map "p" #'pownforge-operation-approve)
    (define-key map "x" #'pownforge-operation-execute)
    map)
  "Keymap for `pownforge-operation-list-mode'.")

(define-derived-mode pownforge-operation-list-mode tabulated-list-mode "PownForge-Operations"
  "Major mode listing pownforge attack operations.
\\{pownforge-operation-list-mode-map}"
  (setq tabulated-list-format
        [("Name" 18 t) ("Nodes" 10 t) ("Actions" 10 t) ("Objective" 40 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--operation-list-entries)
  (tabulated-list-init-header))

(defun pownforge--operation-list-entries ()
  (mapcar (lambda (op)
            (list (plist-get op :name)
                  (vector (plist-get op :name) (plist-get op :nodes)
                          (plist-get op :actions) (plist-get op :objective))))
          (pownforge-parse-operation-list (pownforge--run '("operation" "list") '(:workdir)))))

;;;###autoload
(defun pownforge-operation-list ()
  "Show pownforge attack operations in a tabulated-list buffer.
Press RET to view an operation's nodes/edges/actions/approvals, `c' to
create a new operation, `n'/`e'/`a' to add a node/edge/action, `p' to
approve an action, `x' to execute an approved action."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-operations*")))
    (with-current-buffer buf
      (pownforge-operation-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

(defun pownforge-operation-list-show ()
  "Show the attack operation at point."
  (interactive)
  (let ((name (tabulated-list-get-id)))
    (unless name (user-error "No attack operation on this line"))
    (pownforge-operation-show name)))

;;;###autoload
(defun pownforge-operation-show (name)
  "Show attack operation NAME's nodes/edges/actions/approvals
(`pownforge operation show NAME')."
  (interactive (list (completing-read "Operation: " (pownforge--operation-names) nil t)))
  (let ((output (pownforge--run (list "operation" "show" name) '(:workdir))))
    (with-current-buffer (get-buffer-create (format "*pownforge-operation: %s*" name))
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert output))
      (special-mode)
      (pop-to-buffer (current-buffer)))))

;;;###autoload
(defun pownforge-operation-create (name objective engagement)
  "Create a new attack operation NAME with OBJECTIVE/ENGAGEMENT.
Never executes anything -- only registers a name that
`pownforge-operation-add-node'/`-add-edge'/`-add-action' can then attach a
graph and candidate actions to."
  (interactive
   (list (read-string "New operation name: ")
         (read-string "Objective (blank for none): ")
         (read-string "Engagement (blank for none): ")))
  (let ((args (append (list "operation" "create" name)
                       (unless (string-empty-p objective) (list "--objective" objective))
                       (unless (string-empty-p engagement) (list "--engagement" engagement)))))
    (message "%s" (string-trim (pownforge--run args '(:workdir))))))

;;;###autoload
(defun pownforge-operation-add-node (name node-id target label)
  "Add NODE-ID (an already-registered TARGET, with optional LABEL) to
operation NAME's graph.  Purely descriptive bookkeeping -- grants no
execution right beyond TARGET's own `allowed_plugins'."
  (interactive
   (list (completing-read "Operation: " (pownforge--operation-names) nil t)
         (read-string "Node id: ")
         (completing-read "Target: "
                           (mapcar (lambda (r) (plist-get r :name))
                                   (pownforge-parse-target-list
                                    (pownforge--run '("target" "list") '(:config))))
                           nil t)
         (read-string "Label (blank for none): ")))
  (let ((args (append (list "operation" "add-node" name node-id "--target" target)
                       (unless (string-empty-p label) (list "--label" label)))))
    (message "%s" (string-trim (pownforge--run args '(:config :workdir))))))

;;;###autoload
(defun pownforge-operation-add-edge (name source destination capabilities)
  "Add an edge between two nodes of operation NAME, connecting their
already-added SOURCE/DESTINATION *targets* (not node ids -- see
`pownforge-operation-add-node').  CAPABILITIES is a comma-separated list of
Capability values (blank for the CLI's own default: network-pivot).
Purely descriptive: recording an edge grants no execution or pivot right
on its own -- a PIVOT action still needs its own approval and, at execute
time, an Engagement both targets belong to."
  (interactive
   (let ((name (completing-read "Operation: " (pownforge--operation-names) nil t))
         (target-names (lambda ()
                          (mapcar (lambda (r) (plist-get r :name))
                                  (pownforge-parse-target-list
                                   (pownforge--run '("target" "list") '(:config)))))))
     (list name
           (completing-read "Source target: " (funcall target-names) nil t)
           (completing-read "Destination target: " (funcall target-names) nil t)
           (read-string "Capabilities (comma separated, blank for default): "))))
  (let ((args (append (list "operation" "add-edge" name "--source" source "--destination" destination)
                       (unless (string-empty-p capabilities) (list "--capabilities" capabilities)))))
    (message "%s" (string-trim (pownforge--run args '(:config :workdir))))))

;;;###autoload
(defun pownforge-operation-add-action (name action-id action-name target phase kind plugin)
  "Add a candidate ACTION-ID/ACTION-NAME (PHASE/KIND, against TARGET, with an
optional PLUGIN for `scan' actions) to operation NAME.  Never executes
anything -- only `pownforge-operation-execute' does, and only once the
action has been approved via `pownforge-operation-approve'."
  (interactive
   (let* ((name (completing-read "Operation: " (pownforge--operation-names) nil t))
          (action-id (read-string "Action id: "))
          (action-name (read-string "Action name: "))
          (target (completing-read "Target: "
                                    (mapcar (lambda (r) (plist-get r :name))
                                            (pownforge-parse-target-list
                                             (pownforge--run '("target" "list") '(:config))))
                                    nil t))
          (phase (completing-read "Phase: "
                                   '("recon" "initial-access" "execution" "privilege-escalation"
                                     "credential-access" "discovery" "lateral-movement"
                                     "persistence" "impact")
                                   nil t))
          (kind (completing-read "Kind: " '("scan" "manual" "pivot") nil t nil nil "scan"))
          (plugin (if (equal kind "scan")
                      (completing-read "Plugin: "
                                        (mapcar (lambda (p) (plist-get p :name))
                                                (pownforge-parse-plugin-list
                                                 (pownforge--run '("plugin" "list") '())))
                                        nil t)
                    "")))
     (list name action-id action-name target phase kind plugin)))
  (let ((args (append (list "operation" "add-action" name action-id action-name
                             "--target" target "--phase" phase "--kind" kind)
                       (unless (string-empty-p plugin) (list "--plugin" plugin)))))
    (message "%s" (string-trim (pownforge--run args '(:config :workdir))))))

;;;###autoload
(defun pownforge-operation-approve (name action-id approved-by note)
  "Record human approval for ACTION-ID in operation NAME.
Required before `pownforge-operation-execute' will run it."
  (interactive
   (let ((name (completing-read "Operation: " (pownforge--operation-names) nil t)))
     (list name
           (read-string "Action id: ")
           (read-string "Approved by: ")
           (read-string "Note (blank for none): "))))
  (let ((args (append (list "operation" "approve" name action-id "--approved-by" approved-by)
                       (unless (string-empty-p note) (list "--note" note)))))
    (message "%s" (string-trim (pownforge--run args '(:workdir))))))

;;;###autoload
(defun pownforge-operation-execute (name action-id command output tool)
  "Execute approved ACTION-ID in operation NAME.
A SCAN action runs through the existing ScanRunner, same as
`pownforge-scan'.  MANUAL/PIVOT actions never execute anything -- OUTPUT
must already be the transcript of what a human ran with an external TOOL
\(optionally naming the COMMAND); this only records it, exactly like
`pownforge-result-import'."
  (interactive
   (let ((name (completing-read "Operation: " (pownforge--operation-names) nil t)))
     (list name
           (read-string "Action id: ")
           (read-string "Command (MANUAL/PIVOT only, blank for none): ")
           (read-string "Output (MANUAL/PIVOT only, blank for none): ")
           (read-string "Tool (MANUAL/PIVOT only, blank for none): "))))
  (let ((args (append (list "operation" "execute" name action-id)
                       (unless (string-empty-p command) (list "--command" command))
                       (unless (string-empty-p output) (list "--output" output))
                       (unless (string-empty-p tool) (list "--tool" tool)))))
    (message "%s" (string-trim (pownforge--run args '(:config :workdir))))))

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

;;; Validation primitives (docs/handbook.md §15)

(defun pownforge-parse-primitive-list (output)
  "Parse `pownforge primitive list' OUTPUT into a list of plists.
Only the primitive header lines are parsed (id\\t[category]\\tmax_level=..\\t
description); the indented `    --option ...' lines are skipped."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           unless (string-prefix-p " " line)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :id (nth 0 fields)
                           :category (string-trim (or (nth 1 fields) "") "\\[" "\\]")
                           :max-level (string-remove-prefix "max_level=" (or (nth 2 fields) ""))
                           :description (or (nth 3 fields) "")))))

(defun pownforge-parse-primitive-runs (output)
  "Parse `pownforge primitive runs' OUTPUT into a list of plists."
  (cl-loop for line in (split-string (string-trim output) "\n" t)
           when (string-match-p "\t" line)
           collect (let ((fields (split-string line "\t")))
                     (list :run-id (nth 0 fields)
                           :primitive (nth 1 fields)
                           :target (nth 2 fields)
                           :level (string-remove-prefix "level=" (or (nth 3 fields) ""))
                           :created-at (or (nth 4 fields) "")))))

(defun pownforge--primitive-list-entries ()
  (mapcar (lambda (p)
            (list (plist-get p :id)
                  (vector (plist-get p :id)
                          (plist-get p :category)
                          (plist-get p :max-level)
                          (plist-get p :description))))
          (pownforge-parse-primitive-list (pownforge--run '("primitive" "list") '()))))

(define-derived-mode pownforge-primitive-list-mode tabulated-list-mode "PownForge-Primitives"
  "Major mode listing available pownforge validation primitives."
  (setq tabulated-list-format
        [("Id" 22 t) ("Category" 16 t) ("Max level" 12 t) ("Description" 60 t)])
  (setq tabulated-list-padding 2)
  (setq tabulated-list-entries #'pownforge--primitive-list-entries)
  (tabulated-list-init-header))

;;;###autoload
(defun pownforge-primitive-list ()
  "Show available validation primitives in a tabulated-list buffer."
  (interactive)
  (let ((buf (get-buffer-create "*pownforge-primitives*")))
    (with-current-buffer buf
      (pownforge-primitive-list-mode)
      (tabulated-list-print))
    (pop-to-buffer buf)))

;;;###autoload
(defun pownforge-primitive-run (primitive target level options cves)
  "Run PRIMITIVE against TARGET at LEVEL, persist it, and show the summary.
OPTIONS is a space-separated key=value string (blank for none); CVES is a
comma-separated CVE list (blank for none).  PownForge never runs an exploit
-- a primitive's ceiling is a controlled observation (see docs/handbook.md
§15)."
  (interactive
   (let* ((primitives (pownforge-parse-primitive-list
                        (pownforge--run '("primitive" "list") '())))
          (primitive (completing-read "Primitive: "
                                       (mapcar (lambda (p) (plist-get p :id)) primitives)
                                       nil t))
          (targets (pownforge-parse-target-list (pownforge--run '("target" "list") '(:config))))
          (target (completing-read "Target: "
                                    (mapcar (lambda (r) (plist-get r :name)) targets) nil t))
          (level (completing-read "Level: " '("detection" "validation" "execution") nil t
                                   nil nil "validation"))
          (options (read-string "Options (key=value, space separated, blank for none): "))
          (cves (read-string "CVEs (comma separated, blank for none): ")))
     (list primitive target level options cves)))
  (let* ((option-args (cl-loop for kv in (split-string (or options "") " " t)
                               append (list "--option" kv)))
         (cve-args (cl-loop for c in (split-string (or cves "") "[, ]+" t)
                            append (list "--cve" c)))
         (args (append (list "primitive" "run" primitive "--target" target "--level" level)
                        option-args cve-args))
         (out (pownforge--run args '(:config :workdir)))
         (buf (get-buffer-create "*pownforge-primitive-run*")))
    (with-current-buffer buf
      (special-mode)
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert out))
      (goto-char (point-min)))
    (pop-to-buffer buf)
    (message "%s" (string-trim (car (split-string out "\n"))))))

;;;###autoload
(defun pownforge-result-import (target command output tool phase cves artifacts)
  "Record a human-performed exploit step (`pownforge result import').
PownForge never runs COMMAND; this only records what the operator reports.
TOOL/PHASE may be blank.  CVES is a comma-separated CVE list; ARTIFACTS is a
list of file paths to attach (hashed into the evidence store).  See
docs/handbook.md §13."
  (interactive
   (let* ((targets (pownforge-parse-target-list (pownforge--run '("target" "list") '(:config))))
          (target (completing-read "Target: "
                                    (mapcar (lambda (r) (plist-get r :name)) targets) nil t))
          (command (read-string "Command (recorded, never executed): "))
          (output (read-string "Output/transcript: "))
          (tool (read-string "Tool (blank for none): "))
          (phase (completing-read "Phase (blank for none): "
                                   '("" "discovery" "vuln-confirm" "exploit" "initial-access"
                                     "privilege-escalation" "lateral-movement" "persistence" "impact")
                                   nil t))
          (cves (read-string "CVEs (comma separated, blank for none): "))
          (artifacts (let (files (f t))
                        (while (and f (not (string-empty-p f)))
                          (setq f (read-file-name "Artifact (blank to finish): " nil "" nil))
                          (unless (string-empty-p f) (push (expand-file-name f) files)))
                        (nreverse files))))
     (list target command output tool phase cves artifacts)))
  (let* ((args (append (list "result" "import" "--target" target
                              "--command" command "--output" output)
                        (unless (string-empty-p (or tool "")) (list "--tool" tool))
                        (unless (string-empty-p (or phase "")) (list "--phase" phase))
                        (cl-loop for c in (split-string (or cves "") "[, ]+" t)
                                 append (list "--cve" c))
                        (cl-loop for a in artifacts append (list "--artifact" a))))
         (out (pownforge--run args '(:config :workdir))))
    (message "%s" (string-trim out))
    out))

;;;###autoload
(defun pownforge-result-tag (run-id cves remove)
  "Add (or with REMOVE, delete) CVE tags on RUN-ID.
CVES is a comma-separated CVE list.  Tags are correlation labels for the
engagement report's CVE exposure matrix."
  (interactive
   (let ((run-id (completing-read "Run id: "
                                   (mapcar (lambda (r) (plist-get r :run-id))
                                           (pownforge-parse-result-list
                                            (pownforge--run '("result" "list") '(:workdir))))
                                   nil t))
         (cves (read-string "CVEs (comma separated): "))
         (remove (y-or-n-p "Remove these CVEs instead of adding? ")))
     (list run-id cves remove)))
  (let* ((cve-args (cl-loop for c in (split-string (or cves "") "[, ]+" t)
                            append (list "--cve" c)))
         (args (append (list "result" "tag" run-id) cve-args
                        (when remove (list "--remove"))))
         (out (pownforge--run args '(:workdir))))
    (message "%s" (string-trim out))
    out))

(provide 'pownforge)

;;; pownforge.el ends here
