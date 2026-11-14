# HTML resource origin policy review

Post-session AI-assisted verification, separate from model tests. Python3.14.3; dependency-lock and frozen import paths retained. Set PYTHONPATH to matching frozen source plus verification/html-origin-r1, then python -B -m pytest -q -s test_html_origin_review.py:52 pass4 failures (all literal Unicode C1 control range omissions in a[href]/img[src], same root cause). All expected attributes observed through actual HTMLParser parse of real Cleaner output, not raw string search. Model origin tests65 pass; upstream excluding model tests461 pass3 xfail. Scopes not summed. Tests are offline, no link requests or services. Recording demo.py prints real remaining C1 attributes and exits1;75-second video is continuous/openly automated.

No model source changed after freeze. No automatic submission; user review required.


冻结产物提交：https://github.com/9873199/html-resource-origin-policy/commit/b61240bfd6e56e02b10de06bfb2c4391cfaf7b39
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
