;;; pownforge-test.el --- ERT tests for pownforge.el -*- lexical-binding: t; -*-

;;; Commentary:

;; Run with:
;;   emacs --batch -L emacs -L emacs/tests -l ert -l emacs/tests/pownforge-test.el \
;;     -f ert-run-tests-batch-and-exit
;; (see `make emacs-test').
;;
;; Parsing functions are tested against literal strings copied from real
;; `pownforge' output (see docs/handbook.md §5 and the fixtures in
;; tests/test_plugins.py on the Python side). Process-invoking functions are
;; tested against emacs/tests/fixtures/fake-pownforge, a stub shell script
;; that reproduces the same output shapes without needing a Python
;; environment or real scan targets.

;;; Code:

(require 'ert)
(require 'org)
(require 'pownforge)

(defvar pownforge-test--fixtures-dir
  (expand-file-name "fixtures" (file-name-directory (or load-file-name buffer-file-name))))

(defmacro pownforge-test-with-fake-cli (&rest body)
  "Run BODY with `pownforge-executable' pointed at the fake CLI stub."
  `(let ((pownforge-executable
          (expand-file-name "fake-pownforge" pownforge-test--fixtures-dir)))
     ,@body))

;;; Parsers

(ert-deftest pownforge-test-parse-target-list ()
  (let ((targets (pownforge-parse-target-list
                   (concat
                    "lab-web\turl\thttp://lab-web:3000\tplugins=web, nuclei\ttype=web\tenv=local-lab\n"
                    "kind-lab\thost\tkind-pownforge-lab\tplugins=kubernetes\ttype=kubernetes\tenv=local-lab\n"))))
    (should (= (length targets) 2))
    (should (equal (plist-get (nth 0 targets) :name) "lab-web"))
    (should (equal (plist-get (nth 0 targets) :plugins) "web, nuclei"))
    (should (equal (plist-get (nth 1 targets) :type) "kubernetes"))
    (should (equal (plist-get (nth 1 targets) :environment) "local-lab"))))

(ert-deftest pownforge-test-parse-target-list-empty ()
  (should (equal (pownforge-parse-target-list "no targets registered; use `pownforge target add`\n")
                 nil)))

(ert-deftest pownforge-test-parse-target-list-dash-type ()
  (let ((targets (pownforge-parse-target-list
                   "lab\thost\t127.0.0.1\tplugins=any\ttype=-\tenv=local-lab\n")))
    (should (equal (plist-get (car targets) :type) "-"))
    (should (equal (plist-get (car targets) :plugins) "any"))))

(ert-deftest pownforge-test-parse-plugin-list ()
  (let ((plugins (pownforge-parse-plugin-list
                   (concat "network\tv1\tok\tnmap-based network recon\n"
                           "nuclei\tv1\tmissing tool (nuclei)\ttemplate-based vulnerability detection\n"))))
    (should (= (length plugins) 2))
    (should (equal (plist-get (nth 0 plugins) :version) "1"))
    (should (equal (plist-get (nth 1 plugins) :status) "missing tool (nuclei)"))))

(ert-deftest pownforge-test-parse-result-list ()
  (let ((runs (pownforge-parse-result-list
               "run001\t2026-09-22T10:00:00+00:00\tlab-web\tnuclei\n")))
    (should (= (length runs) 1))
    (should (equal (plist-get (car runs) :run-id) "run001"))
    (should (equal (plist-get (car runs) :plugin) "nuclei"))))

(ert-deftest pownforge-test-parse-result-list-empty ()
  (should (equal (pownforge-parse-result-list "no runs recorded yet\n") nil)))

(ert-deftest pownforge-test-parse-audit-list ()
  (let ((violations (pownforge-parse-audit-list
                      "v1\t2026-09-22T09:00:00+00:00\thost\tnetwork\tnot registered\n")))
    (should (= (length violations) 1))
    (should (equal (plist-get (car violations) :reason) "not registered"))))

(ert-deftest pownforge-test-parse-run-id ()
  (should (equal (pownforge-parse-run-id "run d05b35c10e74 completed (exit=0)\n")
                 "d05b35c10e74"))
  (should (equal (pownforge-parse-run-id
                  "| Starting Nmap 7.991\n| Nmap done\nrun abc123 completed (exit=0)\n")
                 "abc123"))
  (should (null (pownforge-parse-run-id "error: something went wrong\n"))))

(ert-deftest pownforge-test-parse-playbook-list ()
  (let ((playbooks (pownforge-parse-playbook-list
                     (concat "web-adaptive\t2 steps\tnuclei -> sqlmap, but only if high+\n"
                             "web-baseline\t3 steps\tnetwork -> web -> nuclei\n"))))
    (should (= (length playbooks) 2))
    (should (equal (plist-get (nth 0 playbooks) :name) "web-adaptive"))
    (should (equal (plist-get (nth 0 playbooks) :steps) "2 steps"))
    (should (equal (plist-get (nth 1 playbooks) :description) "network -> web -> nuclei"))))

(ert-deftest pownforge-test-parse-playbook-run-ids ()
  (should (equal (pownforge-parse-playbook-run-ids
                   (concat "[1/2] network: run aaaaaaaaaaaa completed (exit=0)\n"
                           "[2/2] web: run bbbbbbbbbbbb completed (exit=0)\n"
                           "playbook 'p' finished: 2/2 steps succeeded (0 skipped, 0 failed)\n"))
                 '("aaaaaaaaaaaa" "bbbbbbbbbbbb")))
  (should (equal (pownforge-parse-playbook-run-ids
                   "[1/2] nuclei: run cccccccccccc completed (exit=0)\n[2/2] sqlmap: SKIPPED (condition not met)\n")
                 '("cccccccccccc")))
  (should (null (pownforge-parse-playbook-run-ids "error: no playbook named 'nope'\n"))))

(ert-deftest pownforge-test-parse-attack-session-list ()
  (let ((sessions (pownforge-parse-attack-session-list
                    "op-1\t1 stages\tinitial foothold via Shellshock\n")))
    (should (= (length sessions) 1))
    (should (equal (plist-get (car sessions) :name) "op-1"))
    (should (equal (plist-get (car sessions) :stages) "1 stages"))
    (should (equal (plist-get (car sessions) :description) "initial foothold via Shellshock"))))

(ert-deftest pownforge-test-parse-attack-session-list-empty ()
  (should (equal (pownforge-parse-attack-session-list
                   "no attack sessions recorded yet; use `pownforge attack-session create`\n")
                 nil)))

(ert-deftest pownforge-test-severity-and-status-mapping ()
  (should (= (pownforge-severity-priority "critical") ?A))
  (should (= (pownforge-severity-priority "high") ?A))
  (should (= (pownforge-severity-priority "medium") ?B))
  (should (= (pownforge-severity-priority "info") ?C))
  (should (equal (pownforge-status-to-todo "confirmed") "DONE"))
  (should (equal (pownforge-status-to-todo "false-positive") "CANCELLED"))
  (should (equal (pownforge-status-to-todo "needs-review") "TODO")))

;;; Process helpers against the fake CLI

(ert-deftest pownforge-test-run-to-string-success ()
  (pownforge-test-with-fake-cli
   (should (string-match-p "lab-web" (pownforge--run '("target" "list") '(:config))))))

(ert-deftest pownforge-test-run-to-string-failure-signals-user-error ()
  (pownforge-test-with-fake-cli
   (let ((err (should-error (pownforge--run-to-string '("fail")) :type 'user-error)))
     (should (string-match-p "boom" (error-message-string err))))))

(ert-deftest pownforge-test-global-args-respects-accepts ()
  (let ((pownforge-config-file "/tmp/targets.yaml")
        (pownforge-workdir "/tmp/work"))
    (should (equal (pownforge--global-args '(:config)) (list "--config" "/tmp/targets.yaml")))
    (should (equal (pownforge--global-args '(:workdir)) (list "--workdir" "/tmp/work")))
    (should (equal (pownforge--global-args '()) nil))
    (should (equal (pownforge--global-args '(:config :workdir))
                    (list "--config" "/tmp/targets.yaml" "--workdir" "/tmp/work")))))

;;; Result rendering

(ert-deftest pownforge-test-result-show-renders-findings-and-properties ()
  (pownforge-test-with-fake-cli
   (unwind-protect
       (progn
         (pownforge-result-show "run001")
         (with-current-buffer "*pownforge-run: run001*"
           (let ((text (buffer-string)))
             (should (string-match-p "Run:      run001" text))
             (should (string-match-p "Critical RCE template match" text))
             ;; Sorted severity-first: critical finding appears before medium.
             (should (< (string-match "Critical RCE" text) (string-match "Exposed admin panel" text)))
             (should (string-match-p "Nuclei Engine Version: v3.11.1" text)))
           (goto-char (point-min))
           (search-forward "Critical RCE")
           (should (equal (get-text-property (point) 'pownforge-run-id) "run001"))
           (should (equal (get-text-property (point) 'pownforge-finding-id) "f2"))))
     (when (get-buffer "*pownforge-run: run001*")
       (kill-buffer "*pownforge-run: run001*")))))

;;; Org integration

(ert-deftest pownforge-test-findings-to-org-inserts-outline-with-properties ()
  (pownforge-test-with-fake-cli
   (with-temp-buffer
     (org-mode)
     (pownforge-findings-to-org "run001")
     (let ((text (buffer-string)))
       (should (string-match-p "\\* Run run001: lab-web / nuclei" text))
       (should (string-match-p "\\*\\* TODO \\[#A\\] Critical RCE template match  :critical:tool:" text))
       (should (string-match-p ":POWNFORGE_RUN_ID: run001" text))
       (should (string-match-p ":POWNFORGE_FINDING_ID: f2" text))))))

(ert-deftest pownforge-test-review-finding-in-org-at-point-calls-cli-and-sets-todo ()
  (pownforge-test-with-fake-cli
   (with-temp-buffer
     (org-mode)
     (pownforge-findings-to-org "run001")
     (goto-char (point-min))
     (search-forward "Critical RCE")
     (org-back-to-heading t)
     (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) "confirmed")))
       (pownforge-review-finding-in-org-at-point))
     (should (equal (org-get-todo-state) "DONE")))))

;;; Live scan (async process + filter/sentinel)

(ert-deftest pownforge-test-scan-live-tails-output-and-resolves-run-id ()
  (pownforge-test-with-fake-cli
   (let (buf)
     (unwind-protect
         (progn
           (setq buf (pownforge-scan "irrelevant-target" "live-ok" ""))
           (with-timeout (5 (ert-fail "scan process did not finish in time"))
             (while (null (buffer-local-value 'pownforge--scan-run-id buf))
               (accept-process-output nil 0.05)))
           (with-current-buffer buf
             (should (equal pownforge--scan-run-id "abc123"))
             (should (string-match-p "line one" (buffer-string)))
             (should (string-match-p "line two" (buffer-string)))))
       (when (buffer-live-p buf) (kill-buffer buf))))))

(ert-deftest pownforge-test-scan-sentinel-handles-missing-run-id-without-erroring ()
  "Regression test: `process-status' returns a symbol, not a string; the
sentinel's no-run-id branch used to pass it through `string-trim' and
signal wrong-type-argument instead of annotating the buffer."
  (pownforge-test-with-fake-cli
   (let (buf)
     (unwind-protect
         (progn
           (setq buf (pownforge-scan "irrelevant-target" "live-noid" ""))
           (with-timeout (5 (ert-fail "scan process did not finish in time"))
             (while (not (with-current-buffer buf (string-match-p "\\[exit\\]" (buffer-string))))
               (accept-process-output nil 0.05)))
           (with-current-buffer buf
             (should (null pownforge--scan-run-id))
             (should (string-match-p "no run id this time" (buffer-string)))))
       (when (buffer-live-p buf) (kill-buffer buf))))))

(ert-deftest pownforge-test-playbook-run-live-tails-output-and-collects-run-ids ()
  (pownforge-test-with-fake-cli
   (let (buf)
     (unwind-protect
         (progn
           (setq buf (pownforge-playbook-run "web-baseline" "lab-web"))
           (with-timeout (5 (ert-fail "playbook run process did not finish in time"))
             (while (not (with-current-buffer buf
                           (string-match-p "to open a step's result" (buffer-string))))
               (accept-process-output nil 0.05)))
           (with-current-buffer buf
             (should (equal (pownforge-parse-playbook-run-ids (buffer-string))
                            '("aaaaaaaaaaaa" "bbbbbbbbbbbb")))))
       (when (buffer-live-p buf) (kill-buffer buf))))))

(ert-deftest pownforge-test-playbook-run-open-result-prompts-when-multiple-ids ()
  (pownforge-test-with-fake-cli
   (let (buf opened)
     (unwind-protect
         (progn
           (setq buf (pownforge-playbook-run "web-baseline" "lab-web"))
           (with-timeout (5 (ert-fail "playbook run process did not finish in time"))
             (while (not (with-current-buffer buf
                           (string-match-p "to open a step's result" (buffer-string))))
               (accept-process-output nil 0.05)))
           (with-current-buffer buf
             (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) "bbbbbbbbbbbb"))
                       ((symbol-function 'pownforge-result-show) (lambda (id) (setq opened id))))
               (pownforge-playbook-run-open-result)))
           (should (equal opened "bbbbbbbbbbbb")))
       (when (buffer-live-p buf) (kill-buffer buf))))))

;;; Attack sessions (record/track already-recorded runs)

(ert-deftest pownforge-test-attack-session-list-entries-runs-fake-cli ()
  (pownforge-test-with-fake-cli
   (let ((entries (pownforge--attack-session-list-entries)))
     (should (= (length entries) 1))
     (should (equal (car (car entries)) "op-1")))))

(ert-deftest pownforge-test-attack-session-show-renders-stages ()
  (pownforge-test-with-fake-cli
   (pownforge-attack-session-show "op-1")
   (with-current-buffer "*pownforge-attack-session: op-1*"
     (unwind-protect
         (progn
           (should (string-match-p "engagement: eng-1" (buffer-string)))
           (should (string-match-p "lab-web / nuclei \\[exploit\\]" (buffer-string))))
       (kill-buffer)))))

(ert-deftest pownforge-test-attack-session-create-calls-cli-with-options ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "created attack session 'op-2'")))
       (pownforge-attack-session-create "op-2" "test session" "eng-1"))
     (should (equal (car calls)
                     '("attack-session" "create" "op-2"
                       "--description" "test session" "--engagement" "eng-1"))))))

(ert-deftest pownforge-test-attack-session-create-omits-blank-options ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "created attack session 'op-3'")))
       (pownforge-attack-session-create "op-3" "" ""))
     (should (equal (car calls) '("attack-session" "create" "op-3"))))))

(ert-deftest pownforge-test-attack-session-add-stage-calls-cli ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "added stage 1 (run001) to attack session 'op-1'")))
       (pownforge-attack-session-add-stage "op-1" "run001" "initial recon"))
     (should (equal (car calls)
                     '("attack-session" "add-stage" "op-1" "run001" "--label" "initial recon"))))))

(ert-deftest pownforge-test-attack-session-report-opens-file ()
  (pownforge-test-with-fake-cli
   (let (opened-path)
     (cl-letf (((symbol-function 'find-file) (lambda (path) (setq opened-path path))))
       (pownforge-attack-session-report "op-1"))
     (should (equal opened-path "/tmp/fake-pownforge-attack-session-op-1.md")))))

;;; Attack operations (graph of nodes/edges/candidate actions + approval)

(ert-deftest pownforge-test-parse-operation-list ()
  (let ((ops (pownforge-parse-operation-list
              "op-1\t2 nodes\t1 actions\trecon test\n")))
    (should (= (length ops) 1))
    (should (equal (plist-get (car ops) :name) "op-1"))
    (should (equal (plist-get (car ops) :nodes) "2 nodes"))
    (should (equal (plist-get (car ops) :actions) "1 actions"))
    (should (equal (plist-get (car ops) :objective) "recon test"))))

(ert-deftest pownforge-test-parse-operation-list-empty ()
  (should (equal (pownforge-parse-operation-list
                   "no attack operations recorded yet; use `pownforge operation create`\n")
                 nil)))

(ert-deftest pownforge-test-operation-list-entries-runs-fake-cli ()
  (pownforge-test-with-fake-cli
   (let ((entries (pownforge--operation-list-entries)))
     (should (= (length entries) 1))
     (should (equal (car (car entries)) "op-1")))))

(ert-deftest pownforge-test-operation-show-renders-detail ()
  (pownforge-test-with-fake-cli
   (pownforge-operation-show "op-1")
   (with-current-buffer "*pownforge-operation: op-1*"
     (unwind-protect
         (progn
           (should (string-match-p "nodes=2 edges=1 actions=1 approvals=1" (buffer-string)))
           (should (string-match-p "edge lab-web -> lab-db" (buffer-string))))
       (kill-buffer)))))

(ert-deftest pownforge-test-operation-create-calls-cli-with-options ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "created attack operation 'op-2'")))
       (pownforge-operation-create "op-2" "recon test" "eng-1"))
     (should (equal (car calls)
                     '("operation" "create" "op-2"
                       "--objective" "recon test" "--engagement" "eng-1"))))))

(ert-deftest pownforge-test-operation-create-omits-blank-options ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "created attack operation 'op-3'")))
       (pownforge-operation-create "op-3" "" ""))
     (should (equal (car calls) '("operation" "create" "op-3"))))))

(ert-deftest pownforge-test-operation-add-node-calls-cli ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "added node 'n1' (lab-web)")))
       (pownforge-operation-add-node "op-1" "n1" "lab-web" "entry point"))
     (should (equal (car calls)
                     '("operation" "add-node" "op-1" "n1" "--target" "lab-web"
                       "--label" "entry point"))))))

(ert-deftest pownforge-test-operation-add-edge-calls-cli ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "added edge 'lab-web' -> 'lab-db'")))
       (pownforge-operation-add-edge "op-1" "lab-web" "lab-db" "network-pivot"))
     (should (equal (car calls)
                     '("operation" "add-edge" "op-1" "--source" "lab-web"
                       "--destination" "lab-db" "--capabilities" "network-pivot"))))))

(ert-deftest pownforge-test-operation-add-action-calls-cli ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "added action 'a1'")))
       (pownforge-operation-add-action "op-1" "a1" "recon scan" "lab-web" "recon" "scan" "network"))
     (should (equal (car calls)
                     '("operation" "add-action" "op-1" "a1" "recon scan"
                       "--target" "lab-web" "--phase" "recon" "--kind" "scan"
                       "--plugin" "network"))))))

(ert-deftest pownforge-test-operation-add-action-manual-omits-plugin ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "added action 'a2'")))
       (pownforge-operation-add-action "op-1" "a2" "manual foothold" "lab-web"
                                        "initial-access" "manual" ""))
     (should (equal (car calls)
                     '("operation" "add-action" "op-1" "a2" "manual foothold"
                       "--target" "lab-web" "--phase" "initial-access" "--kind" "manual"))))))

(ert-deftest pownforge-test-operation-approve-calls-cli ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "approved action 'a1'")))
       (pownforge-operation-approve "op-1" "a1" "operator" "looks fine"))
     (should (equal (car calls)
                     '("operation" "approve" "op-1" "a1"
                       "--approved-by" "operator" "--note" "looks fine"))))))

(ert-deftest pownforge-test-operation-execute-calls-cli ()
  (pownforge-test-with-fake-cli
   (let (calls)
     (cl-letf (((symbol-function 'pownforge--run)
                (lambda (args _accepts) (push args calls) "completed action 'a1' (run=exec001)")))
       (pownforge-operation-execute "op-1" "a1" "" "uid=0(root)" "manual-exploit"))
     (should (equal (car calls)
                     '("operation" "execute" "op-1" "a1"
                       "--output" "uid=0(root)" "--tool" "manual-exploit"))))))

(ert-deftest pownforge-test-operation-report-opens-file ()
  (pownforge-test-with-fake-cli
   (let (opened-path)
     (cl-letf (((symbol-function 'find-file) (lambda (path) (setq opened-path path))))
       (pownforge-operation-report "op-1"))
     (should (equal opened-path "/tmp/fake-pownforge-operation-op-1.md")))))

;;; Walkthrough (multi-run narrative)

(ert-deftest pownforge-test-walkthrough-generate-with-explicit-run-ids ()
  (pownforge-test-with-fake-cli
   (let ((answers (list "run001" "" "html"))
         calls
         opened-path)
     (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) (pop answers)))
               ((symbol-function 'pownforge--run-to-string)
                (lambda (args) (push args calls) "wrote /tmp/fake-walkthrough.md"))
               ((symbol-function 'find-file) (lambda (path) (setq opened-path path))))
       (pownforge-walkthrough-generate))
     ;; run-id loop collected "run001" then stopped on the blank answer, so
     ;; the target prompt must never have fired (it would have consumed
     ;; "html" as the target, leaving the format prompt starved).
     (should (equal (car calls) '("walkthrough" "generate" "run001" "--format" "html")))
     (should (equal opened-path "/tmp/fake-walkthrough.md")))))

(ert-deftest pownforge-test-walkthrough-generate-with-target ()
  (pownforge-test-with-fake-cli
   (let ((answers (list "" "lab-web" "markdown"))
         calls)
     (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) (pop answers)))
               ((symbol-function 'pownforge--run-to-string)
                (lambda (args) (push args calls) "wrote /tmp/fake-walkthrough.md"))
               ((symbol-function 'find-file) #'ignore))
       (pownforge-walkthrough-generate))
     ;; blank run-id answer immediately stops the loop, so the target prompt
     ;; must fire next.
     (should (equal (car calls) '("walkthrough" "generate" "--target" "lab-web" "--format" "markdown"))))))

;;; Validation primitives

(ert-deftest pownforge-test-parse-primitive-list ()
  (let ((ps (pownforge-parse-primitive-list
              (concat
               "http.oob-interaction\t[oob-interaction]\tmax_level=validation\tOOB HTTP interaction check\n"
               "    --option path (required): Absolute path containing {callback}\n"
               "jndi.oob-lookup-probe\t[oob-interaction]\tmax_level=validation\tLog4Shell-class indicator\n"))))
    (should (= (length ps) 2))
    (should (equal (plist-get (nth 0 ps) :id) "http.oob-interaction"))
    (should (equal (plist-get (nth 0 ps) :category) "oob-interaction"))
    (should (equal (plist-get (nth 0 ps) :max-level) "validation"))
    (should (equal (plist-get (nth 1 ps) :id) "jndi.oob-lookup-probe"))))

(ert-deftest pownforge-test-parse-primitive-runs ()
  (let ((rs (pownforge-parse-primitive-runs
              "p001\thttp.oob-interaction\tlab-web\tlevel=validation\t2026-09-22T11:00:00+00:00\n")))
    (should (= (length rs) 1))
    (should (equal (plist-get (car rs) :run-id) "p001"))
    (should (equal (plist-get (car rs) :primitive) "http.oob-interaction"))
    (should (equal (plist-get (car rs) :level) "validation"))))

(ert-deftest pownforge-test-primitive-list-entries ()
  (pownforge-test-with-fake-cli
   (let ((entries (pownforge--primitive-list-entries)))
     (should (= (length entries) 2))
     (should (equal (aref (nth 1 (nth 0 entries)) 0) "http.oob-interaction")))))

(ert-deftest pownforge-test-primitive-run-builds-args ()
  (let (calls)
    (cl-letf (((symbol-function 'pownforge--run-to-string)
               (lambda (args) (push args calls)
                 "primitive run p001 completed (level_reached=validation)"))
              ((symbol-function 'pop-to-buffer) #'ignore))
      (pownforge-primitive-run "http.oob-interaction" "lab-web" "validation"
                                "path=/fetch?url={callback}" "CVE-2021-44228"))
    (should (equal (car calls)
                   '("primitive" "run" "http.oob-interaction" "--target" "lab-web"
                     "--level" "validation" "--option" "path=/fetch?url={callback}"
                     "--cve" "CVE-2021-44228")))))

(ert-deftest pownforge-test-result-import-builds-args ()
  (let (calls)
    (cl-letf (((symbol-function 'pownforge--run-to-string)
               (lambda (args) (push args calls) "run imp001 recorded (target=lab, plugin=manual)")))
      (pownforge-result-import "lab" "msfconsole -x run" "got shell" "msfconsole"
                                "exploit" "CVE-2021-44228" '("/tmp/proof.txt")))
    (should (equal (car calls)
                   '("result" "import" "--target" "lab" "--command" "msfconsole -x run"
                     "--output" "got shell" "--tool" "msfconsole" "--phase" "exploit"
                     "--cve" "CVE-2021-44228" "--artifact" "/tmp/proof.txt")))))

(ert-deftest pownforge-test-result-import-omits-blank-optionals ()
  (let (calls)
    (cl-letf (((symbol-function 'pownforge--run-to-string)
               (lambda (args) (push args calls) "run imp002 recorded (target=lab, plugin=manual)")))
      (pownforge-result-import "lab" "cmd" "out" "" "" "" nil))
    (should (equal (car calls)
                   '("result" "import" "--target" "lab" "--command" "cmd" "--output" "out")))))

(ert-deftest pownforge-test-result-tag-builds-args ()
  (let (calls)
    (cl-letf (((symbol-function 'pownforge--run-to-string)
               (lambda (args) (push args calls) "run run001 cves: CVE-2021-44228")))
      (pownforge-result-tag "run001" "CVE-2021-44228, CVE-2022-22965" nil)
      (pownforge-result-tag "run001" "CVE-2021-44228" t))
    (should (equal (nth 1 calls)
                   '("result" "tag" "run001" "--cve" "CVE-2021-44228" "--cve" "CVE-2022-22965")))
    (should (equal (car calls)
                   '("result" "tag" "run001" "--cve" "CVE-2021-44228" "--remove")))))

(provide 'pownforge-test)

;;; pownforge-test.el ends here
