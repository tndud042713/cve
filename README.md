<center>

# CVE-2016-0728
## Analysis Report
## Analysis report on join_session_keyring function

#### First reporter : Yevgeny Pats(2016-01-19 22:09:04 +0000)

#### Athor : tndud042713

#### Date Created : 2022.06.29

<br>
<br>
<br>

</center>

* * *
<br>
# Index
### &nbsp;&nbsp;1. Introduce
### &nbsp;&nbsp;2. Code audit
### &nbsp;&nbsp;3. PoC
### &nbsp;&nbsp;4. Exploit
### &nbsp;&nbsp;5. Reference
<br>

* * * 

<br>
# 1. Introduce
<br>
<br>

<p>&nbsp;&nbsp;2016년 1월 19일 Yevgeny Pats가 발견한 vulnerability이다. 이 vulnerability는 2016년보다 이전인 2012년부터 존재했었던 vulnerability이지만, 2016년에 발견되었다. 이 vulnerability은 security/keys/process_keys.c에 있는 join_session_keyring function 이 certain error case 에서 object references를 mishandles 하면서 생기는 vulnerability로 알려져있다.
</p>
<p>
&nbsp;&nbsp;CVE-2016-0728은 CVSS Common Vulnerability Scoring System (공통 취약점 등급 시스템)
에서 각각 version에 따라 높은 등급을 받은 취약점이다. CVSS2.0에서는 7.2 HIGH score를 받았고, CVSS3.x에서는 7.8 HIGH score를 받았다. 이 vulnerability가 HIGH score를 받은 원인을 분석해 보면 Linux OS PC와 Android device의 약 70%에 영향을 줄 수 있기 때문이다. 
</p>
<br>

***
# 2. Code audit
<br>
<br>

<p>&nbsp;&nbsp;Vulnerability의 분석을 위해서 join_session_keyring function이 certain error case에서 object references를 mishandles 하면서 생기는 vulnerability에 주목해서 vulnerability를 확인한다. security/keys/process_keys.c를 비교하면서 왜 새로운 부분이 생겨났는지 확인해보려고 한다.</p>
