;;;; cl-bedrock.asd

(asdf:defsystem #:cl-bedrock
  :description "Common Lisp library for Amazon Bedrock"
  :author "João Galego <jgalego1990@gmail.com>"
  :license "MIT"
  :version "0.1.0"
  :serial t
  :depends-on (#:babel
               #:cl-json
               #:cl-json-helper
               #:dexador
               #:ironclad
               #:local-time
			   #:quri)
  :components ((:file "package")
               (:file "cl-bedrock")))