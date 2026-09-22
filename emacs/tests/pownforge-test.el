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

(provide 'pownforge-test)

;;; pownforge-test.el ends here
