char help[] =

"\n\t++ Available Options ++\n\n"
"\n\t-arp\t\t2개의 target host 사이의 arp 통신을 가로챈다.\n"
"\n\t-ip\t\t2개의 target host 사이의 ip 통신을 가로챈다.\n"
"\n\t-Hscn\t\ttarget network의 host를 스캔한다.\n"
"\n\t-Pscn\t\ttarget host의 포트를 스캔한다.\n"
"\n\t-dns\t\ttarget host의 dns 패킷을 가로채 특정 웹사이트로 접속을 유도한다.\n"
"\n\t-drdos\t\ttarget host에게 web server를 이용해 무수히 많은 웹페이지 요청 패킷을 보낸다.\n"
"\n\n\n\t++ Usage ++\n\n"
"\n\t./cameleon -arp [target ip_addr] [target ip_addr]\n"
"\n\t./cameleon -ip [target ip_addr] [target ip_addr]\n"
"\n\t./cameleon -Hscn [target network 주소] [net mask]\n"
"\n\t./cameleon -Pscn [target ip_addr]\n"
"\n\t./cameleon -dns [target ip_addr] [Gateway ip_addr]\n"
"\n\t./cameleon -drdos [Gateway ip_addr] [target ip_addr]\n\n";
