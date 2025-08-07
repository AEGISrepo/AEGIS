import json
import time
import openai
from aegis_prompt_helper import *
import concurrent
from functools import lru_cache
import pickle
from thefuzz import fuzz, process
import zerorpc
import re

client = openai.OpenAI()


@lru_cache
def getProbesDict():
    with open(settings['probes-pickle-path'], "rb") as f:
        probes = pickle.load(f)
    return probes

# Find possible eBPF probes based on function name or system call name


@lru_cache
def findProbe(name: str):
    probes = getProbesDict()
    keyslist = list(probes.keys())
    ans = process.extractOne(name, keyslist, scorer=fuzz.ratio)
    return ans


def findPossibleProbes(namelist: list):
    anslist = []
    probes = getProbesDict()

    for name in namelist:
        name = name.strip()
        if len(name) <= 2:
            continue
        probnames = [name, f"do_sys_{name}",
                     f"sys_enter_{name}", f"sys_exit_{name}"]

        for probname in probnames:
            ans = findProbe(probname)
            if not ans:
                continue
            # ('do_sys_open', 100)
            if ans[1] == 100:
                anslist.append(ans[0])
                break
            elif ans[1] > 70:
                anslist.append(ans[0])

    ans = []
    for shortname in anslist:
        ans.append(probes[shortname])
# [[('kfunc:vmlinux:do_sys_open', 'int dfd\nconst char * filename\nint flags\numode_t mode\nlong int retval'), ('kprobe:do_sys_open', ''), ('kretfunc:vmlinux:do_sys_open', 'int dfd\nconst char * filename\nint flags\numode_t mode\nlong int retval'), ('kretprobe:do_sys_open', '')]]
    return ans

# Finding function definition implementations by function name


@lru_cache
def getZerorpcClient():
    c = zerorpc.Client(timeout=60)
    c.connect("tcp://127.0.0.1:24242")
    return c


def checkZerorpc():
    try:
        c = getZerorpcClient()
        return c.echo("hello") == "hello"
    except Exception as e:
        logger.error(e)
        return False


def findFunctionDefinition(namelist: list):
    c = getZerorpcClient()
    ans = []
    logger.info(f"{namelist}")
    for name in namelist:
        ret = c.findFunc(name.strip())
        if ret:
            if len(ret) > 3000:
                logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                ret = ret[:3000]
            ans.append(ret)

    for name in namelist:
        # _
        if re.match(r'^[A-Z_]+$', name.strip()):
            ret = c.findDefine(name.strip())
            if ret:
                if len(ret) > 3000:
                    logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                    ret = ret[:3000]
                ans.append(ret)

    return ans


# Finding structure definitions by structure name
def findStructDefinition(namelist: list):
    c = getZerorpcClient()
    ans = []
    logger.info(f"{namelist}")
    for name in namelist:
        ret = c.findStruct(name.strip())
        if ret:
            if len(ret) > 3000:
                logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                ret = ret[:3000]
            ans.append(ret)
    return ans


# Finding the definition of a macro or enumeration value by name
def findMacroOrEnumDefinition(namelist: list):
    c = getZerorpcClient()
    ans = []
    logger.info(f"{namelist}")
    for name in namelist:
        ret = c.findDefine(name.strip())
        if ret:
            if len(ret) > 3000:
                logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                ret = ret[:3000]
            ans.append(ret)
    return ans


CHATTOOLS = [
    {
        "type": "function",
                "function": {
                    "name": "findPossibleProbes",
                    "description": "Find possible eBPF probes based on function name or system call name",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "namelist": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "a python list array of function name or system call name"
                            }
                        },
                        "required": ["namelist"],
                    }
                }
    },
    {
        "type": "function",
                "function": {
                    "name": "findFunctionDefinition",
                    "description": "Finding function definition implementations by function name",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "namelist": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "a python list array of  kernel function name"
                            }
                        },
                        "required": ["namelist"],
                    },
                }
    },
    {
        "type": "function",
                "function": {
                    "name": "findStructDefinition",
                    "description": "Finding structure definitions by structure name",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "namelist": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "a python list array of kernel struct name"
                            }
                        },
                        "required": ["namelist"],
                    },
                }
    },
    {
        "type": "function",
                "function": {
                    "name": "findMacroOrEnumDefinition",
                    "description": "Finding the definition of a macro or enumeration value by name",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "namelist": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                            }
                        },
                        "required": ["namelist"],
                    }
                }
    }
]

CHATTOOLSFUNS = {
    "findPossibleProbes": findPossibleProbes,
    "findFunctionDefinition": findFunctionDefinition,
    "findStructDefinition": findStructDefinition,
    "findMacroOrEnumDefinition": findMacroOrEnumDefinition,
}


def check(s):
    if s == None or s == "" or len(s) == 0:
        return False
    return True


def checkBpftraceComplier(prog: str):
    prog = removeMarkdownFormat(prog)
    c = getZerorpcClient()
    res = c.checkBpftrace(prog)
    logger.info(f"checkBpftraceComplier:\n{prog}\nThe compiler result: {res}")
    return res


def getProgFromResponse(resp: str):
    """
Here is the bpftrace code to monitor the vulnerability:

```bpftrace
kfunc:seq_buf_alloc
{
    $size = (unsigned long)args.size;
    if ($size > MAX_RW_COUNT) {
        printf("CVE-2021-33909 maybe triggered by pid[%d] comm[%s]\n", pid, comm);
    }
}
```

This bpftrace program attaches to the `seq_buf_alloc` function, checks the `size` argument, and prints an alert if the `size` exceeds `MAX_RW_COUNT`, including the CVE ID, process ID, and command name.

"""
    # "```\w*\s+([\s|\S]+)```"gm
    rex = re.compile(r"```\w*\s+([\s|\S]+)```")
    res = rex.findall(resp)
    if len(res) > 0:
        return "\n".join(res)
    else:
        return resp


def removeMarkdownFormat(prog: str):
    prog = getProgFromResponse(prog).strip()

    def escape_newlines_in_quotes(match):
        string = str(match.group(0))
        if '\\n' in string:
            return string
        return match.group(0).replace('\n', '\\n')

    prog = re.sub(
        r'"(.*?)"', escape_newlines_in_quotes, prog, flags=re.DOTALL)

    if prog.startswith("```"):
        prog = prog[prog.find("\n"):]
        if prog.endswith("```"):
            prog = prog[:prog.rfind("```")]
    return prog


def processSpecificError(errmsg: str):
    ret = "\n\n"
    # unexpected for
    if "unexpected for" in errmsg or "foreach" in errmsg:
        ret += """
{Bpftrace syntax rule of loop part}
[loops]

[for]

The current version of bpftrace does not support the for loop syntax. Currently, it is not possible to traverse a map.

[while]

Since kernel 5.3 BPF supports loops as long as the verifier can prove they’re bounded and fit within the instruction limit.

In bpftrace, loops are available through the `while` statement.

```
while (condition) {
  block;
}
```

Within a while-loop the following control flow statements can be used:

- continue: skip processing of the rest of the block and jump back to the evaluation of the conditional
- break: Terminate the loop


```
i:s:1 {
  $i = 0;
  while ($i <= 100) {
    printf("%d ", $i);
    if ($i > 5) {
      break;
    }
    $i++
  }
  printf("\n");
}
```


"""

    # ERROR: Unknown identifier: 'AF_NETLINK'
    rex = re.compile(r"ERROR: Unknown identifier: ?'?(\w+)'?")
    res = rex.findall(errmsg)
    for item in res:
        structlist = findStructDefinition([item,])
        deflist = findMacroOrEnumDefinition([item,])
        for st in structlist:
            ret += f"{st}\n"
        for de in deflist:
            ret += f"{de}\n"
        ret += "\n"

    # ERROR: Unknown function: access_ok
    rex = re.compile(r"ERROR: Unknown function: ?'?(\w+)'?")
    res = rex.findall(errmsg)
    for item in res:
        funclist = findFunctionDefinition([item,])
        for f in funclist:
            ret += f"{f}\n"
        ret += "\n"

    # ERROR: Cannot resolve unknown type "__kernel_key_t"
    rex = re.compile(r'ERROR: Cannot resolve unknown type "?([\w|\s]+)"?')
    res = rex.findall(errmsg)
    for item in res:
        # if item is C-lang type
        c_types_identifiers = [
            "char", "signed char", "unsigned char", "short", "short int", "signed short",
            "signed short int", "unsigned short", "unsigned short int", "int", "signed",
            "signed int", "unsigned", "unsigned int", "long", "long int", "signed long",
            "signed long int", "unsigned long", "unsigned long int", "long long", "long long int",
            "signed long long", "signed long long int", "unsigned long long", "unsigned long long int",
            "float", "double", "long double", "void", "bool", "ptrdiff_t", "size_t", "wchar_t",
            "wint_t", "nullptr_t", "max_align_t", "int8_t", "int16_t", "int32_t", "int64_t",
            "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int_least8_t", "int_least16_t",
            "int_least32_t", "int_least64_t", "uint_least8_t", "uint_least16_t", "uint_least32_t",
            "uint_least64_t", "int_fast8_t", "int_fast16_t", "int_fast32_t", "int_fast64_t",
            "uint_fast8_t", "uint_fast16_t", "uint_fast32_t", "uint_fast64_t", "intptr_t",
            "uintptr_t", "intmax_t", "uintmax_t", "NULL", "offsetof"]
        if item in c_types_identifiers:
            ret += "uint8,int8,uint16,int16,uint32,int32,uint64,int64\n"
            continue

        structlist = findStructDefinition([item,])
        deflist = findMacroOrEnumDefinition([item,])
        for st in structlist:
            ret += f"{st}\n"
        for de in deflist:
            ret += f"{de}\n"
        ret += "\n"

    # ERROR: Unknown struct/union: 'ext4_inode_info'
    rex = re.compile(r"ERROR: Unknown struct/union: ?'?(\w+)'?")
    res = rex.findall(errmsg)
    for item in res:
        structlist = findStructDefinition([item,])
        for st in structlist:
            ret += f"{st}\n"
        ret += "\n"

    # ERROR: The array index operator [] only accepts literal integer indices.
    if "The array index operator [] only accepts literal integer indices" in errmsg:
        ret += """
[Array access]

Bpftrace does not support the use of variables as indexes of arrays.

Here is an example of the wrong array access syntax.
```
tracepoint:syscalls:sys_enter_execve  
{
    $i = 0;
    while (args->argv[$i] != 0) {  // Wrong, Bpftrace does not support this syntax, like `args->argv[$i]`
        $i++;
    }
    $last_arg = str(args->argv[$i-1]);  // Wrong, Bpftrace does not support this syntax, like `args->argv[$i - 1]`
}
```

The syntactically correct bpftrace that is semantically equivalent to the above is as follows.
```
tracepoint:syscalls:sys_enter_execve
{

    $i = 0;
    while (*(args->argv + $i) != 0 && $i < 128) {  // The correct way is `*(args->argv + $i)` , rather than `args->argv[$i]`. `$i < 128` is added to prevent infinite loops.
        $i++;
    }
    $last_arg = str(*(args->argv + $i - 1));
}
```

Moreever, Because ebpf programs go through a validator, there can't be potentially infinite loops in their programs. Thus, the loop condition must be bounded. The while loop condition in the above program should be added to the `$i < 128` check.

The array index operator [] only accepts literal integer indices. The following bpftrace program is correct.
```
tracepoint:syscalls:sys_enter_execve  
{
    $arg00 = str(args->argv[0]);
    $arg01 = str(args->argv[1]);
    $arg02 = str(args->argv[2]);
}
```


"""

    if "unsigned" in errmsg or "size_t" in errmsg:
        ret += """
[Data Types]

The following fundamental integer types are provided by the language. Integers are internally represented as 64 bit signed. If you need another representation, you may cast to the following built in types:

- uint8
- int8
- uint16
- int16
- uint32
- int32
- uint64
- int64


bpftrace only supports the above basic data types, when you need to do basic data type conversion, you can only use the above types. Here is an example, just to illustrate the syntax.
```
kretprobe:vfs_open
{
    $res = (unsigned long)retval; // Wrong syntax, bpftrace only support type like uint64 ...
    $res = (uint64)retval; // Correct syntax
}
```

For structure members, you may need to convert them to the appropriate type depending on the context, which may be the basic type mentioned above, or a pointer to a structure or other type. The following is an example.

```bpftrace
kfunc:udmabuf_vm_fault
{
    $ubuf = (struct udmabuf *)args->vmf->vma->vm_private_data;
    $pagecount = $ubuf->pagecount;
}
```

"""

    # ERROR: kfunc:decode_data: no BTF data for decode_data
    rex = re.compile(r"ERROR: ?(\S+) ?: no BTF data")
    res = rex.findall(errmsg)
    if len(res):
        ret += "no BTF data means that you can't use kfunc/kretfunc probe here, you may try to use kprobe/kretprobe instead or other probes.\n"
        ret += enhanceProbesInfoViaProg("\n".join(res))
        for item in res:
            shortname = str(item).split(":")[-1]
            funclist = findFunctionDefinition([shortname,])
            for f in funclist:
                ret += f"{f}\n"
            ret += "\n"

    # ERROR: The args builtin can only be used with tracepoint/kfunc/uprobeprobes (kprobe used here)
    if "The args builtin can only be used with" in errmsg:
        ret += """

BPFtrace does not automatically detect function signatures, so users need to manually perform type conversions for arguments. For example, when tracing the `vfs_open` function, users should cast `arg0` to the appropriate type, such as `(struct path *)`, to access the desired fields. BPFtrace relies on available kernel headers for struct support, similar to BCC, but not all structs may be available, requiring manual definitions. 

The `args` builtin is only usable with tracepoint, kfunc, kretfunc.

"""

    # ERROR: Struct/union of type 'struct tcf_proto' does not contain a field named 'handle'
    rex = re.compile(r"ERROR: Struct/union of type '([\s|\w]+)'")
    res = rex.findall(errmsg)
    for item in res:
        name = str(item).split()[-1]
        if name.startswith("_tracepoint_"):
            continue
        structlist = findStructDefinition([name,])
        for st in structlist:
            ret += f"{st}\n"
        ret += "\n"

    if "flex scanner push-back overflow" in errmsg:
        ret += """

`flex scanner push-back overflow`: This problem is usually due to the fact that bpftrace cannot handle a header file included in the program, which may be too large or too complex for bpftrace.

You can try to include other header files, or just extract the information you need instead of including the whole header file.

"""

    logger.info(f"processSpecificError:\n{ret.strip()}")
    return ret.strip()


@lru_cache
def enhanceProbesInfoViaProg(prog: str):
    ret = r"""

Below is information about some bpftrace probes, including their arguments.
These probes may or may not be related to the target. You need to make your own choices.


"""
    cnt = 0
    # \w+:[\w|:]+
    regex = re.compile(r'\w+:[\w|:]+')
    res = regex.findall(prog)
    for item in res:
        item = item.strip()
        shortname = item.split(":")[-1]
        problist = findPossibleProbes([shortname,])
        ctx = str()
        for l in problist:
            for item in l:
                cnt += 1
                # item[0] ,item[1]
                ctx = ctx + f"{item[0]}\n"
                for arg in str(item[1]).split("\n"):
                    ctx = ctx + f"\t{arg}\n"
                ctx += "\n"
        ret += ctx

    if "for (" in prog:
        ret += """

{Bpftrace syntax rule of loop part}
[loops]

[for]

The current version of bpftrace does not support the for loop syntax. Currently, it is not possible to traverse a map.
Don't use for loop syntax in bpftrace program.
"""

    logger.info(f"enhanceProbesInfoViaProg:\n{ret}")
    if cnt:
        return ret.strip()
    else:
        return ""


def interact_with_llm(messages: list):
    for i in range(5):
        try:
            completion = client.chat.completions.create(
                model=settings['model'],
                messages=messages,
                # tools=CHATTOOLS,
                # tool_choice="auto",
                # tool_choice="none",   # Caused by api provider bug, not supported yet
            )

            global TOTALTOKENS
            TOTALTOKENS += completion.usage.total_tokens
            logger.info(f"TOTALTOKENS: {TOTALTOKENS}")
            logger.info(f"{completion.choices[0]}")

            tool_calls = completion.choices[0].message.tool_calls
            if tool_calls:
                logger.info(f"tool_calls: {tool_calls}")
                for tool_call in tool_calls:
                    function_name = tool_call.function.name
                    function_to_call = CHATTOOLSFUNS[function_name]
                    function_args = json.loads(tool_call.function.arguments)
                    function_response = function_to_call(
                        function_args.get('namelist'))
                    tool_dict = {"role": "tool", "tool_call_id": tool_call.id,
                                 "name": function_name, "content": function_response}

                    messages.append(tool_dict)
                    # messages.append(
                    #     {"role": "user", "content": json.dumps(tool_dict)})
                    logger.info(f"{tool_dict}")
                continue

            # reasoning_content = completion.choices[0].message.reasoning_content
            cont = completion.choices[0].message.content
            if not check(cont):
                raise Exception("Response content is None.")

            return cont
        except Exception as e:
            logger.error(f"{e}")
            time.sleep(2**i)
    raise Exception("Should not reach here.")


def debugBpfProg(cveid: str, errorProg, errormsg, tip=None, context=None):
    logger.info(f"[{cveid}] Debugging")
    baseprompt = getDebugPrompt0(cveid)
    """
[[CVE-TIPS]]
[[CVE-CONTEXT]]
[[BUGGY-PROGRAM]]
[[ERROR-MESSAGE]]
    """

    baseprompt = baseprompt.replace("[[CVE-TIPS]]", tip if tip else "None")
    # prompt = prompt.replace("[[CVE-CONTEXT]]", context if context else "None")
    baseprompt = baseprompt.replace("[[BUGGY-PROGRAM]]",
                                    errorProg if errorProg else "None")
    baseprompt = baseprompt.replace("[[ERROR-MESSAGE]]",
                                    errormsg if errormsg else "None")

    context = "" if context is None else context
    probesinfo = enhanceProbesInfoViaProg(errorProg)
    specerrors = processSpecificError(errormsg)
    context += f"{probesinfo}\n{specerrors}"

    prompt = baseprompt.replace(
        "[[CVE-CONTEXT]]", context if context else "None")

    messages = [
        {"role": "system", "content": "You are an expert in the field of computer security and are responsible for understanding my intentions and ultimately debuging the given bpftrace program and then generating the new correct bpftrace program. bpftrace is a high-level tracing language and runtime for Linux based on eBPF. It supports static and dynamic tracing for both the kernel and user-space."},
        {"role": "user", "content": prompt},
    ]

    for i in range(settings['iter-when-fail']):

        logger.info(f"[{cveid}] Debugging Round {i}")

        llmresp = interact_with_llm(messages)

        if not check(llmresp):
            logger.error(f"[{cveid}] genBpfProg's ans in None.")
            raise Exception

        llmresp = removeMarkdownFormat(llmresp)
        compilerres = checkBpftraceComplier(llmresp)
        if compilerres == "PASS":
            logger.info(f"[{cveid}] debugBpfProg's ans is compiler passed.")
            return llmresp

        messages.append({"role": "assistant", "content": llmresp})

        probesinfo = enhanceProbesInfoViaProg(llmresp)
        specerrors = processSpecificError(compilerres)

        enhancedPrompt = f"""
The bpftrace program you generated does not compile; the compiler reports the following error:
{compilerres}

{{Contexts may be useful}}
{probesinfo}

{specerrors}

Please regenerate the bpftrace program according to my target and the compiler error message. Only output the bpftrace program, do not generate any other content.
"""
        messages.append({"role": "user", "content": enhancedPrompt})

    logger.info(f"[{cveid}] failed to debugBpfProg in {
                settings['iter-when-fail']} rounds.")
    return None


def genBpfProgWithMessages(cveid: str, messages: list, debugit=True, tip=None, context=None):
    llmresp = interact_with_llm(messages)

    if not check(llmresp) or context is True:
        logger.error(f"genBpfProgWithMessages get None response.")
        raise Exception

    llmresp = removeMarkdownFormat(llmresp)
    complierres = checkBpftraceComplier(llmresp)
    if complierres == "PASS":
        logger.info(f"BPFTRACE COMPILER PASSED!")
        return llmresp
    elif debugit:
        # Not Pass bpftrace compiler
        return debugBpfProg(cveid, llmresp, complierres, tip, context)
    else:
        return None


def genBpfProg(cveid: str, tip=None, context=None):
    """
[[CVE-TIPS]]
[[CVE-CONTEXT]]
    """

    prompt = getGeneratePrompt0(cveid)
    prompt = prompt.replace("[[CVE-TIPS]]", tip if tip else "None")
    prompt = prompt.replace("[[CVE-CONTEXT]]", context if context else "None")

    messages = [
        {"role": "system", "content": "You are an expert in the field of computer security and are responsible for understanding my intentions and ultimately generating the bpftrace program. bpftrace is a high-level tracing language and runtime for Linux based on eBPF. It supports static and dynamic tracing for both the kernel and user-space."},
        {"role": "user", "content": prompt},
    ]

    return genBpfProgWithMessages(cveid, messages, True, tip, context)


def enhanceAnalysis(content: str):
    if not check(content):
        return content

    words = re.findall(r'\b[A-Z_][A-Z0-9_]+\b', content)

    blocked_terms = ["COMM", "XFRM", "PATH", "BEGIN", "END", "FD", "COMPAT_SYSCALL_DEFINE", "SYSCALL_DEFINE", "NULL", "SIGKILL", "EBPF", "BPF", "BPFTRACE", "CVE", "ID", "PID", "TID", "UID", "GID", "UUID", "MAC", "IP", "URL", "URI", "DNS", "HTTP", "HTTPS", "FTP", "SSH", "SSL", "TLS", "API", "SDK", "JSON", "XML", "JWT", "OAUTH", "SMTP", "POP3", "IMAP", "TCP", "UDP", "ICMP", "VPN", "NAT", "DHCP", "SNMP", "RDP", "SFTP", "LDAP", "MQTT", "REST", "SOAP", "WSDL", "XSD", "HTML", "CSS", "PHP", "SQL", "RAM", "CPU", "GPU", "SSD", "HDD", "BIOS", "UEFI", "ASCII", "GBK", "ISO", "CRC", "MD5", "AES", "RSA", "ECC", "TOR", "PROXY", "FIREWALL", "IDS", "IPS", "SIEM", "DLP", "WAF", "HIDS", "NIDS", "VLAN", "OSPF", "BGP", "ARP", "IGMP", "RIP", "OSI", "LAN", "WAN", "MAN", "PAN", "SAN", "CAN", "DAS", "NAS", "FC", "SATA", "SAS", "SCSI", "IDE", "PCI",
                     "USB", "HDMI", "DVI", "VGA", "DP", "AGP", "ISA", "EISA", "MCA", "VLB", "PCMCIA", "EXPRESSCARD", "THUNDERBOLT", "FIREWIRE", "ETHERNET", "FDDI", "ATM", "FRAME_RELAY", "ISDN", "T1", "E1", "T3", "E3", "CWDM", "DWDM", "SDH", "SONET", "PON", "GPON", "EPON", "APON", "BPON", "FTTH", "FTTB", "FTTC", "FTTN", "FTTD", "FTTP", "GSM", "CDMA", "UMTS", "HSPA", "HSDPA", "HSUPA", "EDGE", "GPRS", "WAP", "MMS", "SMS", "VOIP"]

    filtered_words = [word for word in words if word not in blocked_terms]

    unique_words = list(set(filtered_words))

    if len(unique_words) == 0:
        return content

    deflist = findMacroOrEnumDefinition(unique_words)

    if len(deflist) == 0:
        return content

    logger.info(f"{deflist}")

    enhancestr = """
The following are some definitions from kernel source code. You may or may not need them, judge for yourself.

"""

    for de in deflist:
        enhancestr += f"{de}\n"

    return content + "\n\n" + enhancestr


def getAnalysisViaPatch(cveid: str):
    # lnos = patchToLinenos(cveid)
    analyzePrompt = getAnalyzePatchPromptV1(cveid)

    messages = [
        {"role": "system", "content": "You are an experienced kernel-related developer with extensive experience submitting patches to the kernel forums, and you are familiar with bpftrace, the ebpf monitoring tool, and know the extent of bpftrace's capabilities."},
        {"role": "user", "content": analyzePrompt},
    ]

    logger.info(f"[{cveid}] getAnalysisViaPatch")
    llmresp = interact_with_llm(messages)
    logger.info(f"[{cveid}] \n{llmresp}")
    return enhanceAnalysis(llmresp)


def getAnalysisViaPoC(cveid: str):
    analyzePrompt = getAnalyzePoCPrompt0(cveid)

    messages = [
        {"role": "system", "content": "You are an experienced system security researcher, have a wealth of vulnerability mining and exploitation, penetration experience, familiar with the system attack and defense programs, able to understand the vulnerabilities corresponding to the Proof of Concept and Exploit program logic and program characteristics."},
        {"role": "user", "content": analyzePrompt},
    ]

    logger.info(f"[{cveid}] getAnalysisViaPoC")
    llmresp = interact_with_llm(messages)
    logger.info(f"[{cveid}] \n{llmresp}")
    return enhanceAnalysis(llmresp)


def saveToFile(cveid: str, type: int, prog: str):
    global BASEDIR
    if BASEDIR == None:
        logger.error(f"BASEDIR is None")
        raise Exception

    os.makedirs(f"{BASEDIR}/{cveid}", exist_ok=True)
    with open(f"{BASEDIR}/{cveid}/{cveid}#{type}.bt", "w") as f:
        f.write(prog)

    parts = {0: "Description", 1: "Patch", 2: "PoC"}

    logger.info(f"[{cveid}] Using {parts[type]
                                   }, save to file {cveid}#{type}.bt")


def getFuncName(cveid: str):
    prompt = getFuncNamePrompt0(cveid)
    for i in range(5):
        try:
            completion = client.chat.completions.create(
                model=settings['model'],
                messages=[
                    {"role": "system", "content": "You are an experienced kernel-related developer with extensive experience submitting patches to the kernel forums, and you specialize in understanding and extracting function-related information from text or patch."},
                    {"role": "user", "content": prompt}
                ],
            )
            global TOTALTOKENS
            TOTALTOKENS += completion.usage.total_tokens
            logger.info(f"[{cveid}] Token Usage: {
                        completion.usage.total_tokens}    TOTALTOKENS: {TOTALTOKENS}")
            logger.info(f"[{cveid}] {completion.choices[0]}")
            ans = completion.choices[0].message.content
            if ans == None:
                return None
            if "DO NOT KNOW" in ans.upper():
                return None
            return ans
        except Exception as e:
            logger.error(f"[{cveid}] getFuncName error: {e}")
            time.sleep(2**i)
    raise Exception("Should not happen")


def getDefectiveFunctionName(cveid: str):
    funcname = getFuncName(cveid)
    logger.info(f"[{cveid}] Defective Function: {funcname}")
    return funcname


def processCVE(cveid: str):
    global ALREADYCVEITEMS
    if cveid in ALREADYCVEITEMS:
        # pass
        logger.info(f"[{cveid}] already processed.")
        return

    cveitem = CVEITEMS[cveid]
    # CVE ID,CVE Link,Description,Patch,Patch Link,POC,POC Link,Writeup,Writeup Link,others,,
    logger.info(f"{cveid}")
    gened = []

    if check(cveitem['POC']) or check(cveitem['Writeup']):
        analysisOfPoC = getAnalysisViaPoC(cveid)
        prog = genBpfProg(cveid, analysisOfPoC, None)
        if check(prog):
            #  POC
            gened.append(2)
            saveToFile(cveid, 2, prog)

    if check(cveitem['Patch']):
        analysisOfPatch = getAnalysisViaPatch(cveid)
        if "can not do it" in analysisOfPatch.lower():
            logger.info(f"[{cveid}] AnalysisViaPatch can not do it.")
        else:
            prog = genBpfProg(cveid, analysisOfPatch, True)
            if check(prog):
                gened.append(1)
                saveToFile(cveid, 1, prog)

    if not len(gened):
        funcname = getDefectiveFunctionName(cveid)

        if check(funcname):
            problist = findPossibleProbes([funcname,])
            ctx = """
The following are possible bpftrace probes. These probes may or may not be related to the target. You need to make your own judgment and choose from them or choose another probes.\n"""
            for l in problist:
                for item in l:
                    # item[0] ,item[1]
                    ctx = ctx + f"{item[0]}\n"
                    for arg in str(item[1]).split("\n"):
                        ctx = ctx + f"\t{arg}\n"
                    ctx += "\n"

            logger.info(f"[{cveid}] {ctx}")

            tip = r"""
You can just monitor whether the defective function is called, and if it is, alert the police that the CVE vulnerability may be exploited, and output information such as time, pid,comm, and so on.

Here is an example:
```
kprobe:nft_byteorder_eval
{
    printf("CVE-XXXX-XXXXXX maybe triggered by pid[%d] comm[%s]\n", pid, comm);
}
```
            """
            prog = genBpfProg(cveid, tip, ctx)
            if check(prog):
                gened.append(0)
                saveToFile(cveid, 0, prog)
        else:
            logger.error(
                f"[{cveid}] Can not get function name, thus eBPF can't monitor this CVE.")

    if len(gened):
        logger.info(f"[{cveid}] Generate Success {gened}")
    else:
        logger.warning(f"[{cveid}] Generate Failed")


def main(currency=False):
    cvetodolist = settings['CVELIST']

    if not currency:
        for cveid in cvetodolist:
            processCVE(cveid)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = [executor.submit(processCVE, cveid)
                       for cveid in cvetodolist]

            for fu in concurrent.futures.as_completed(futures):
                retval = fu.result()


if __name__ == "__main__":
    if not checkZerorpc():
        logger.error("zerorpc server is not start yet!")
        exit(1)
    alreadyProcessed()
    prepare()
    main()
    logger.info(
        f"====================================================================")
    logger.info(
        f"====================================================================")
    logger.info(f"Generate process reach the end. {
                TOTALTOKENS} tokens have been used.")
