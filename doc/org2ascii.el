(let ((bufname (car command-line-args-left))
      (target (car (cdr command-line-args-left))))
  (set-buffer (find-file bufname))
  (let ((name (org-ascii-export-to-ascii)))
    (if target
	(rename-file name target t))
    (kill-buffer (current-buffer))))
