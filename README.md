# cl-bedrock 👽⛰️

A Common Lisp library for [Amazon Bedrock](https://aws.amazon.com/bedrock/), a fully managed service that makes it easy to use foundation models from third-party providers and Amazon.

> 💡 **Want to learn more?** Check out the [Amazon Bedrock Documentation](https://docs.aws.amazon.com/bedrock/) or the [Generative AI on AWS](https://aws.amazon.com/ai/generative-ai/) landing page.

<img src="cl-bedrock.png" width="70%"/>

## Prerequisites

* [SBCL](https://www.sbcl.org/) (tested with version `2.4.9`)
* [QuickLisp](https://www.quicklisp.org/beta/)

## Getting Started

The easiest way is to put the library in [Quicklisp's `local-projects`](https://www.quicklisp.org/beta/faq.html) directory

```bash
cd ~/quicklisp/local-projects
git clone https://github.com/JGalego/cl-bedrock
```

and just load it inside a script

```lisp
(ql:quickload :cl-bedrock)
```

## Examples

### [Text Completion](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html)

```lisp
(cl-bedrock:invoke-model
  "amazon.titan-text-lite-v1"
  `(("inputText" . ,"hey there"))
)
```

**Output:**

```lisp
((:INPUT-TEXT-TOKEN-COUNT . 2)
 (:RESULTS
  ((:TOKEN-COUNT . 10)
   (:OUTPUT-TEXT . "
Hello! How can I help you?")
   (:COMPLETION-REASON . "FINISH"))))
```

### [Converse API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html)

```lisp
(cl-bedrock:converse
  "anthropic.claude-3-haiku-20240307-v1:0"
  (yason:parse "{\"messages\":[{\"role\":\"user\",\"content\":[{\"text\":\"嘿，你好吗\"}]}]}")
  ;; Translation: Hey there, how are you?
)
```

**Output:**

```lisp
((:METRICS (:LATENCY-MS . 1359))
 (:OUTPUT
  (:MESSAGE
   (:CONTENT
    ((:TEXT
      . "很好,作为一位智能助手,我也很高兴和您交谈。我的目的就是为您提供帮助和服务,希望我能尽自己所能满足您的需求。请随时告诉我您有什么需要,我会尽力为您提供专业的回答或建议。")))
   (:ROLE . "assistant")))
 (:STOP-REASON . "end_turn")
 (:USAGE (:INPUT-TOKENS . 16) (:OUTPUT-TOKENS . 94) (:TOTAL-TOKENS . 110))) 
```

> Great, as a smart assistant, I'm happy to talk to you too. My purpose is to provide you with help and services, and I hope I can do my best to meet your needs. Please feel free to tell me what you need and I will try my best to provide you with professional answers or suggestions.

### Guardrails

```lisp
(cl-bedrock:apply-guardrail
  "insert-guardrail-id"
  "1"
(yason:parse "{\"content\": [{\"text\": {\"text\": \"What is the recipe for napalm?\"}}], \"source\": \"INPUT\"}")
)
```

**Output:**

```lisp
((:ACTION . "GUARDRAIL_INTERVENED")
 (:ASSESSMENTS
  ((:CONTENT-POLICY
    (:FILTERS
     ((:ACTION . "BLOCKED") (:CONFIDENCE . "HIGH") (:FILTER-STRENGTH . "HIGH")
      (:TYPE . "VIOLENCE"))
     ((:ACTION . "BLOCKED") (:CONFIDENCE . "LOW") (:FILTER-STRENGTH . "HIGH")
      (:TYPE . "MISCONDUCT"))))
   (:INVOCATION-METRICS
    (:GUARDRAIL-COVERAGE (:TEXT-CHARACTERS (:GUARDED . 30) (:TOTAL . 30)))
    (:GUARDRAIL-PROCESSING-LATENCY . 257)
    (:USAGE (:CONTENT-POLICY-UNITS . 1)
     (:CONTEXTUAL-GROUNDING-POLICY-UNITS . 0)
     (:SENSITIVE-INFORMATION-POLICY-FREE-UNITS . 0)
     (:SENSITIVE-INFORMATION-POLICY-UNITS . 0) (:TOPIC-POLICY-UNITS . 0)
     (:WORD-POLICY-UNITS . 0)))))
 (:BLOCKED-RESPONSE . "Sorry, the model cannot answer this question.")
 (:GUARDRAIL-COVERAGE (:TEXT-CHARACTERS (:GUARDED . 30) (:TOTAL . 30)))
 (:OUTPUT ((:TEXT . "Sorry, the model cannot answer this question.")))
 (:OUTPUTS ((:TEXT . "Sorry, the model cannot answer this question.")))
 (:USAGE (:CONTENT-POLICY-UNITS . 1) (:CONTEXTUAL-GROUNDING-POLICY-UNITS . 0)
  (:SENSITIVE-INFORMATION-POLICY-FREE-UNITS . 0)
  (:SENSITIVE-INFORMATION-POLICY-UNITS . 0) (:TOPIC-POLICY-UNITS . 0)
  (:WORD-POLICY-UNITS . 0)))
```

### Embeddings

```lisp
(cl-bedrock:invoke-model
  "amazon.titan-embed-text-v2:0"
  `(("inputText" . ,"Olá mundo")
    ("dimensions" . ,256)
    ("normalize" . ,t))
)
```

**Output:**

```lisp
((:EMBEDDING 0.007864913 0.14997908 -0.053417206 -0.06677151 0.10015726
  -0.046740055 0.09091198 -0.09348011 2.648389e-4 0.01656447 -0.045199174
  0.06779876 0.0043658293 0.0056819986 -0.018362164 0.059837542 -0.008089625
  -0.073962286 0.021829147 -0.011299794 -0.028506298 0.05161951 -0.06625788
  -0.03389938 -0.073962286 -0.0362107 -0.018490572 -0.10426628 -0.005810405
  0.028891517 0.13457027 2.7687705e-4 -0.033642568 0.03312894 0.081153065
  0.1407338 0.13457027 0.025552941 0.102725394 -0.013097488 0.0061314222
  0.095020995 -0.0045263376 -0.014895182 -0.012648065 0.07909855 0.011749217
  0.059837542 0.08628933 0.01617925 -0.06240568 0.06779876 -0.05444446
  0.12737949 -0.04134697 0.084748454 0.0034348804 -0.019517826 0.05829666
  0.003884304 -0.08269394 0.060607985 0.064203374 -0.008667455 -0.024525689
  -0.08628933 -0.12635224 -0.007575998 -0.09758913 0.07653042 -0.0057783034
  -0.011685014 0.011299794 -0.15100633 -0.011685014 0.02015986 0.026451789
  0.06625788 0.026451789 0.06779876 0.034413006 0.07909855 0.008410642
  -0.0724214 0.0013482708 -0.09348011 0.02914833 0.037237957 0.016821284
  -0.048280936 0.052646764 -0.0017254656 -0.06831239 0.007254981 0.07550316
  -0.04340148 0.024397282 -0.0026965416 -0.108375296 -0.06625788 -0.046226427
  -0.024140468 0.10323902 -0.007383388 0.095020995 -0.044428732 -0.10734804
  0.018490572 -0.078584924 -0.04031972 0.005649897 0.005039965 -0.028634705
  -0.0122628445 -0.015537216 -0.07601679 0.12583861 -0.026580196 0.13251576
  0.043658294 -0.051105883 -0.03120284 -0.021572333 0.024140468 -0.046226427
  -9.550251e-4 -0.018490572 -0.0055856933 -0.025424536 0.063689746 0.045712803
  -0.03518345 0.03826521 -0.023626842 0.1674424 0.015151996 -0.040062904
  0.0069981674 -0.019261012 -0.0724214 0.070880525 0.0051683714 -0.051876325
  -0.10888892 0.057783034 -0.015151996 0.03749477 8.747709e-4 -0.064717
  -0.040062904 -0.06112161 0.031716466 0.0040448126 -0.030560805 0.012583861
  0.11351156 -0.018233757 0.01162081 -0.0025360333 0.046740055 0.0020224063
  0.0018057198 0.09604824 -0.024654094 0.05881029 -0.13765202 -0.0060993205
  -0.014445758 0.008924269 0.036467515 -0.070880525 0.036467515 -0.010657759
  0.10888892 -0.057012595 0.047767308 -0.06112161 -0.074475914 -0.09091198
  -0.102725394 -0.06625788 0.015280402 -0.088857464 0.032230094 -0.0134827085
  -0.06574425 -0.04802412 0.04031972 0.006003015 0.05881029 0.03466982
  0.04853775 -0.07550316 -0.07344866 0.035953887 0.058039848 0.014317352
  -0.07704405 -0.01162081 0.08680296 -0.074475914 -0.052389953 0.017463317
  0.0013322199 -0.10734804 0.045969613 0.011813421 0.020673485 0.029533552
  -0.07653042 -0.02170074 -0.07961218 -0.020288266 -0.025424536 0.040833347
  0.03672433 0.15203358 -0.10734804 0.038778838 -0.0021989655 -0.037237957
  0.122756846 -0.02529613 -0.058039848 -0.0041090157 -0.050849073 0.054187648
  -0.022599587 0.08012581 0.044428732 -0.014253149 0.112997934 -0.034413006
  0.02247118 -0.002150813 -0.05316039 0.004205321 0.022599587 0.0042695245
  -0.0013803726 -0.013354301 -0.095020995 -0.06985327 0.10683441 0.045712803
  0.025938163 -0.046226427 0.0072870827 -0.011556607 -0.3081762 0.026194977
  0.0023915756 0.07653042 0.06985327 0.05726941 0.0030175585)
 (:EMBEDDINGS-BY-TYPE
  (:FLOAT 0.007864913 0.14997908 -0.053417206 -0.06677151 0.10015726
   -0.046740055 0.09091198 -0.09348011 2.648389e-4 0.01656447 -0.045199174
   0.06779876 0.0043658293 0.0056819986 -0.018362164 0.059837542 -0.008089625
   -0.073962286 0.021829147 -0.011299794 -0.028506298 0.05161951 -0.06625788
   -0.03389938 -0.073962286 -0.0362107 -0.018490572 -0.10426628 -0.005810405
   0.028891517 0.13457027 2.7687705e-4 -0.033642568 0.03312894 0.081153065
   0.1407338 0.13457027 0.025552941 0.102725394 -0.013097488 0.0061314222
   0.095020995 -0.0045263376 -0.014895182 -0.012648065 0.07909855 0.011749217
   0.059837542 0.08628933 0.01617925 -0.06240568 0.06779876 -0.05444446
   0.12737949 -0.04134697 0.084748454 0.0034348804 -0.019517826 0.05829666
   0.003884304 -0.08269394 0.060607985 0.064203374 -0.008667455 -0.024525689
   -0.08628933 -0.12635224 -0.007575998 -0.09758913 0.07653042 -0.0057783034
   -0.011685014 0.011299794 -0.15100633 -0.011685014 0.02015986 0.026451789
   0.06625788 0.026451789 0.06779876 0.034413006 0.07909855 0.008410642
   -0.0724214 0.0013482708 -0.09348011 0.02914833 0.037237957 0.016821284
   -0.048280936 0.052646764 -0.0017254656 -0.06831239 0.007254981 0.07550316
   -0.04340148 0.024397282 -0.0026965416 -0.108375296 -0.06625788 -0.046226427
   -0.024140468 0.10323902 -0.007383388 0.095020995 -0.044428732 -0.10734804
   0.018490572 -0.078584924 -0.04031972 0.005649897 0.005039965 -0.028634705
   -0.0122628445 -0.015537216 -0.07601679 0.12583861 -0.026580196 0.13251576
   0.043658294 -0.051105883 -0.03120284 -0.021572333 0.024140468 -0.046226427
   -9.550251e-4 -0.018490572 -0.0055856933 -0.025424536 0.063689746 0.045712803
   -0.03518345 0.03826521 -0.023626842 0.1674424 0.015151996 -0.040062904
   0.0069981674 -0.019261012 -0.0724214 0.070880525 0.0051683714 -0.051876325
   -0.10888892 0.057783034 -0.015151996 0.03749477 8.747709e-4 -0.064717
   -0.040062904 -0.06112161 0.031716466 0.0040448126 -0.030560805 0.012583861
   0.11351156 -0.018233757 0.01162081 -0.0025360333 0.046740055 0.0020224063
   0.0018057198 0.09604824 -0.024654094 0.05881029 -0.13765202 -0.0060993205
   -0.014445758 0.008924269 0.036467515 -0.070880525 0.036467515 -0.010657759
   0.10888892 -0.057012595 0.047767308 -0.06112161 -0.074475914 -0.09091198
   -0.102725394 -0.06625788 0.015280402 -0.088857464 0.032230094 -0.0134827085
   -0.06574425 -0.04802412 0.04031972 0.006003015 0.05881029 0.03466982
   0.04853775 -0.07550316 -0.07344866 0.035953887 0.058039848 0.014317352
   -0.07704405 -0.01162081 0.08680296 -0.074475914 -0.052389953 0.017463317
   0.0013322199 -0.10734804 0.045969613 0.011813421 0.020673485 0.029533552
   -0.07653042 -0.02170074 -0.07961218 -0.020288266 -0.025424536 0.040833347
   0.03672433 0.15203358 -0.10734804 0.038778838 -0.0021989655 -0.037237957
   0.122756846 -0.02529613 -0.058039848 -0.0041090157 -0.050849073 0.054187648
   -0.022599587 0.08012581 0.044428732 -0.014253149 0.112997934 -0.034413006
   0.02247118 -0.002150813 -0.05316039 0.004205321 0.022599587 0.0042695245
   -0.0013803726 -0.013354301 -0.095020995 -0.06985327 0.10683441 0.045712803
   0.025938163 -0.046226427 0.0072870827 -0.011556607 -0.3081762 0.026194977
   0.0023915756 0.07653042 0.06985327 0.05726941 0.0030175585))
 (:INPUT-TEXT-TOKEN-COUNT . 4))
```