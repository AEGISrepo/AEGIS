# Under the Dome: Automated Generation of eBPF Programs for Monitoring Vulnerability with AEGIS



## Abstract

Vulnerabilities pose serious risks, yet applying patches in a timely manner can be impractical due to factors such as service disruptions or complex software dependencies. Therefore, 1-day vulnerabilities, which refer to those that have been publicly disclosed, provide opportunities for adversaries. This issue is particularly concerning given the widespread reliance on OSS in modern software development, especially when vulnerabilities in foundational software can affect numerous applications. Effectively monitoring 1-day vulnerability attacks is a practical solution given these concerns.

This paper presents **AEGIS**, an innovative method designed to automate the generation of eBPF programs for monitoring 1-day vulnerabilities. Our work begins with a study of 150 real-world vulnerabilities to summarize monitoring patterns according to different types of information, such as patches, proofs of concept (PoC)/exploit code, and vulnerability descriptions, offering guidance that enhances the generation of effective monitoring programs. **AEGIS** first preprocesses the vulnerability information, then leverages the Large Language Model to analyze it according to the monitoring patterns and generate the monitoring program code. Next, the code is passed to the compiler for verification. If the compilation fails, the Code Debugging phase takes over, addressing issues within the code and performing iterative debugging to automatically produce valid eBPF programs. 







## Content





```
├── aegis_config.py
├── aegis_core.py
├── aegis_prompt_helper.py
├── aegis_rpc.py
├── assets
├── data
├── environment.yml
├── how-to-get-dwarf.md
├── LICENSE
├── probes
├── prompts.toml
├── Readme.md
├── requirements.txt
├── retrieval
├── scripts
│   ├── benchmark.sh
│   ├── bench_repeat.sh
│   ├── cve_spider.py
│   ├── plot.py
│   ├── process_dwarf_debug_frame.py
│   ├── process_dwarf_debug_info.py
│   ├── process_dwarf_debug_line.py
│   ├── run_n.sh
│   └── split_by_compilation_units.py
├── settings.toml
├── tools
│   ├── body_extractor.py
│   ├── callgraphs
│   │   ├── callgraph.py
│   │   ├── callgraphsearch.py
│   │   └── makecallgraph.sh
│   ├── cfa_eval.py
│   ├── dwarf_engine.py
│   ├── dwarfexpressions.txt
│   ├── h2l_mapping.py
│   ├── struct_analyzer.py
│   ├── line_aligner.py
│   └── line_info.py
└── xz-backdoor.md
```





First, download and unzip the Linux Kernel Source Code and place it in the designated folder. The path should be referenced from `kernel-folder` in `aegis_config.py`.



Next, configure the Python dependency environment. We uses Miniconda as the package management software.



Then, run `aegis_rpc.py` in the background to provide related services for aegis.



Additionally, please configure `API_BASE` and `API_KEY` as needed. 



`aegis_core.py` is the core of the generation process, and running it will generate the eBPF monitoring program code.





