
;;;; cl-bedrock.lisp

(in-package #:cl-bedrock)

(defparameter *dex-keep-alive* nil)
(defparameter *dex-verbose* nil)
(defparameter *hash-algorithm* "AWS4-HMAC-SHA256")
(defparameter *nl* (format nil "~c" #\Newline))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Helper functions ;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;
;;; Generic
;;;

(defun getenv (name &optional default)
  "Obtains the current value of the POSIX environment variable NAME.
  Adapted from https://lispcookbook.github.io/cl-cookbook/os.html"
  (declare (type (or string symbol) name))
  (let ((name (string name)))
      (or #+abcl (ext:getenv name)
         #+ccl (ccl:getenv name)
         #+clisp (ext:getenv name)
         #+cmu (unix:unix-getenv name) ; since CMUCL 20b
         #+ecl (si:getenv name)
         #+gcl (si:getenv name)
         #+mkcl (mkcl:getenv name)
         #+sbcl (sb-ext:posix-getenv name)
         default)))

(defun trim-white (s)
  "Removes any leading or trailing whitespace."
  (string-trim '(#\Space #\Tab) s))

(defun safe-url-encode (s)
  "Encode URLs safely."
  (format nil "~{~a~^/~}"
    (mapcar #'quri:url-encode 
      (uiop:split-string s :separator "/"))))

;;;
;;; Dates & Times
;;;

(defun aws-timestamp (the-time)
  "Converts the current UTC time into ISO 8601 format (YYYYMMDD'T'HHMMSS'Z')
  http://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html"
  (local-time:format-timestring nil the-time
    :format '(:year (:month 2) (:day 2) "T" (:hour 2) (:min 2) (:sec 2) "Z")
    :timezone local-time:+utc-zone+))

(defun aws-datestamp (the-time)
  "Converts the current UTC time into a date format (YYYYMMDD)"
  (local-time:format-timestring nil the-time
    :format '(:year (:month 2) (:day 2))
    :timezone local-time:+utc-zone+))

;;;
;;; HTTP stuff
;;;

(defun json-decode-octets (octets)
  "Turns an octet stream into a JSON string."
  (let ((string (babel:octets-to-string octets :encoding :utf-8)))
    (if (equalp string "")
      nil
      (json:decode-json-from-string string))))

(defun make-aws-host (service-code region-code)
  "Generate regional service endpoint host.
  https://docs.aws.amazon.com/general/latest/gr/rande.html"
  (concatenate 'string service-code "." region-code ".amazonaws.com"))

(defun make-aws-endpoint (service-code region-code &key (protocol "https"))
  "Generates a regional service endpoint.
  https://docs.aws.amazon.com/general/latest/gr/rande.html"
  (concatenate 'string protocol "://" (make-aws-host service-code region-code)))

(defun make-aws-url (service-code region-code &key (protocol "https") (target "/"))
  "Creates a request URL to a regional service endpoint."
  (concatenate 'string (make-aws-endpoint service-code region-code :protocol protocol) target))

(defun post (url headers content)
  "Sends a POST request to a specified url."
  (handler-case
    (multiple-value-bind (result code)
      (dex:post url
            :headers headers
            :content content
            :force-binary t
            :keep-alive *dex-keep-alive*
            :verbose *dex-verbose*)
      (values (json-decode-octets result) code nil))
    (dex:http-request-failed (e)
      (values nil (dex:response-status e) (json-decode-octets (dex:response-body e))))))

;;
;; Encryption
;;

(defun pad-hex-string (hs)
  "Ensure the hex string has at least 64 characters with leading zeroes."
  (format nil "~64,1,0,'0@a" hs))

(defun hex-sha256-hash (vector_ba)
  "Secure Hash Algorithm (SHA) cryptographic hash function with lowercase base 16 encoding."
  (pad-hex-string (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 vector_ba))))

(defun hmac-sha256 (msg key)
  "Computes HMAC on a message by using the SHA256 algorithm with the provided signing key."
  (let ((hmac (ironclad:make-hmac key :sha256)))
    (ironclad:update-hmac hmac (babel:string-to-octets msg :encoding :utf-8))
    (ironclad:hmac-digest hmac)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; AWS SigV4 Signing ;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun create-credential-scope (the-time region service)
  "Creates a credential scope, which restricts the resulting signature to the specified region and service."
  (format nil "~a/~a/~a/aws4_request" (aws-datestamp the-time) region service))

(defun create-canonical-request (http-verb canonical-uri canonical-query-string canonical-headers-string signed-headers-string hashed-payload)
  "Arranges the contents of the request (host, action, headers, &c.) into a standard canonical format."
  (concatenate 'string
    http-verb *nl*
    (safe-url-encode canonical-uri) *nl* 
    canonical-query-string *nl*
    canonical-headers-string *nl*
    signed-headers-string *nl*
    hashed-payload))

(defun derive-signing-key (secret-key the-time region service)
  "Derives a signing key by performing a succession of keyed hash operations (HMAC operations)
  on the request date, Region, and service, with the AWS secret access key as the key for the
  initial hashing operation."
  (let ((key (babel:string-to-octets (concatenate 'string "AWS4" secret-key) :encoding :utf-8))
    (date (aws-datestamp the-time)))
    (hmac-sha256 "aws4_request" (hmac-sha256 service (hmac-sha256 region (hmac-sha256 date key))))))

(defun trim-downcase-header (header)
  "Returns the first header trimmed and using lowercase."
  (cons (string-downcase (trim-white (car header))) (cdr header)))

(defun format-canonical-header-string (canonical-headers &optional (result ""))
  "Returns the canonical headers separated by newlines."
  (let ((header (first canonical-headers)))
    (if (null header)
    result
    (format-canonical-header-string (rest canonical-headers) (format nil "~a~a:~a~c" result (car header) (cdr header) #\Newline)))))

(defun canonical-headers (headers)
  "Returns the request headers and their values in canonical format."
  (sort (mapcar #'trim-downcase-header headers) #'string< :key #'car))

(defun format-canonical-signed-headers-string (canonical-headers &optional (result "") (separator ""))
  "Returns an alphabetically sorted, semicolon-separated list of lowercase request header names."
  (let ((header (first canonical-headers)))
    (if (null header)
    result
    (format-canonical-signed-headers-string (rest canonical-headers) (format nil "~a~a~a" result separator (car header)) ";"))))

(defun create-string-to-sign (algorithm amz-time credential-scope canonical-request)
  "Creates a string to sign with the canonical request and extra information such as the algorithm, 
  request date, credential scope, and the hash of the canonical request."
  (concatenate 'string 
    algorithm *nl*
    amz-time *nl*
    credential-scope *nl*
    (hex-sha256-hash (babel:string-to-octets canonical-request :encoding :utf-8))))

(defun calculate-signature (string-to-sign signing-key)
  "Calculates the signature by performing a keyed hash operation on the string to sign."
  (pad-hex-string (ironclad:byte-array-to-hex-string (hmac-sha256 string-to-sign signing-key))))

(defun create-authorization-string (http-verb aws-host canonical-uri base-headers content the-time amz-time region service access-key secret-key)
  "Creates the Authorization string for the request."
  (when (and access-key secret-key)
    (let* 
      ((canonical-headers (canonical-headers (cons (cons "host" aws-host) base-headers)))
       (signed-headers-string (format-canonical-signed-headers-string canonical-headers))
       (hashed-payload (hex-sha256-hash (babel:string-to-octets content :encoding :utf-8)))
       (canonical-header-string (format-canonical-header-string canonical-headers))
       (algorithm *hash-algorithm*)
       (canonical-request (create-canonical-request http-verb canonical-uri "" canonical-header-string signed-headers-string hashed-payload))
       (credential-scope (create-credential-scope the-time region service))
       (string-to-sign (create-string-to-sign algorithm amz-time credential-scope canonical-request))
       (signing-key (derive-signing-key secret-key the-time region service))
       (signature (calculate-signature string-to-sign signing-key)))
      (concatenate 'string algorithm " " "Credential=" access-key "/" credential-scope ", SignedHeaders=" signed-headers-string ", Signature=" signature))))

(defun create-authorization-header (http-verb aws-host target base-headers content the-time amz-time region service access-key secret-key)
  "Creates the Authorization header for the request."
  (let 
    ((authorization-string (create-authorization-string http-verb aws-host target base-headers content the-time amz-time region service access-key secret-key)))
    (when authorization-string
      (list (cons "Authorization" authorization-string)))))

(defun aws-sigv4-post (service region target content &key (endpoint-prefix service) (content-type "application/json") (accept "application/json")  (access-key nil) (secret-key nil) (session-token nil) (the-time (local-time:now)))
  "Sends an AWS SigV4-signed POST request."
  (assert (equal (null access-key) (null secret-key)))
  (let* 
    ((aws-host (make-aws-host endpoint-prefix region))
     (aws-url (make-aws-url endpoint-prefix region :target target))
     (content (cl-json:encode-json-to-string (or content (xjson:json-empty))))
     (amz-time (aws-timestamp the-time))
     (base-headers `(("Accept" . ,accept)
                     ("Content-Type" . ,content-type)
                     ("X-Amz-Date" . ,amz-time))))
    (if session-token (setf base-headers (cons (cons "X-Amz-Security-Token" session-token) base-headers)))
    (multiple-value-bind (result_js result-code response_js)
      (post 
        aws-url
        (append 
          base-headers
          (create-authorization-header
            "POST" aws-host target base-headers content the-time amz-time region service access-key secret-key))
        content)
      (if (equal result-code 200)
        (if result_js
          (values result_js result-code response_js)
          (values t result-code response_js))
        (values result_js result-code response_js)))))

;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Amazon Bedrock ;;;;
;;;;;;;;;;;;;;;;;;;;;;;;

(defun invoke-model (model-id body &key (content-type "application/json") (accept "application/json") (access-key nil) (secret-key nil) (session-token nil) (region nil))
  "Invokes a specified Amazon Bedrock model to run inference.
  https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html"
  (aws-sigv4-post
    "bedrock"
    (getenv "AWS_REGION" region)
    (format nil "/model/~a/invoke" (quri:url-encode model-id))
    body
    :endpoint-prefix "bedrock-runtime"
    :access-key (getenv "AWS_ACCESS_KEY_ID" access-key)
    :secret-key (getenv "AWS_SECRET_ACCESS_KEY" secret-key)
    :session-token (getenv "AWS_SESSION_TOKEN" session-token)))

(defun converse (model-id body &key (access-key nil) (secret-key nil) (session-token nil) (region nil))
  "Sends messages to a specified Amazon Bedrock model.
  https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html"
  (aws-sigv4-post
    "bedrock"
    (getenv "AWS_REGION" region)
    (format nil "/model/~a/converse" (quri:url-encode model-id))
    body
    :endpoint-prefix "bedrock-runtime"
    :access-key (getenv "AWS_ACCESS_KEY_ID" access-key)
    :secret-key (getenv "AWS_SECRET_ACCESS_KEY" secret-key)
    :session-token (getenv "AWS_SESSION_TOKEN" session-token)))

(defun apply-guardrail (guardrail-identifier guardrail-version body &key (access-key nil) (secret-key nil) (session-token nil) (region nil))
  "Applies an Amazon Bedrock Guardrail to stop harmful content.
  https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ApplyGuardrail.html"
  (aws-sigv4-post
    "bedrock"
    (getenv "AWS_REGION" region)
    (format nil "/guardrail/~a/version/~a/apply" guardrail-identifier guardrail-version)
    body
    :endpoint-prefix "bedrock-runtime"
    :access-key (getenv "AWS_ACCESS_KEY_ID" access-key)
    :secret-key (getenv "AWS_SECRET_ACCESS_KEY" secret-key)
    :session-token (getenv "AWS_SESSION_TOKEN" session-token)))