"""`python -m goah_qr` 的入口。

与 `[project.scripts]` 里的 `goah-qr` 指向同一个 main —— 两条路径必须有
完全相同的行为，否则"没装包的人"和"装了包的人"会看到两个不一样的工具。
"""

from .cli import main

raise SystemExit(main())
