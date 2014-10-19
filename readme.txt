
Copyright 2014 KH-Academy 정보보안 1기 김영환, 최용혁, 곽진성


* 본 프로그램은 정보보안 수업 내용을 보다 효과적으로 학습하기 위해 제작한 실습 과제로써 
  다양한 공격기법을 효과적으로 시연할 수 있는 공격 툴이다. 본 프로그램을 수업 외 사용 할 경우 
  법적인 제제를 받을 수 있으며 그 책임은 전적으로 본인에게 있음을 알린다.



* How to Compile

  1. libpcap 라이브러리를 설치한다. ( http://www.tcpdump.org/release/libpcap-1.6.1.tar.gz )

  2. KH_CAMELEON 디렉터리를 다운로드한다.

  3. makefile이 존재하므로 터미널 창에서 즉시 컴파일 할 수 있다.

     ex) #> make




* How to Use

  1. 컴파일 후 원하는 기능에 따라 옵션을 선택하여 실행한다. ( --help 참조 ) 

  2. 옵션을 입력하지 않거나 target ip를 입력하지 않을 경우 세그먼트 오류가 날 수 있으니 
     반드시 --help옵션을 통하여 사용법을 확인한다.

  3. 실행 종료 후 반드시 프로세스 목록을 확인하여 백그라운드에서 작동하고 있지 않은지 확인한다.





* Function

  1. 현재 본 프로그램은 ARP Spoofing 방식으로 타겟 호스트의 패킷을 캡쳐하는 환경에서 작동한다.

  2. Host Scanning : target network의 host를 스캔한다.

  3. Port Scanning : target host의 포트를 스캔한다.

  4. DNS Spoofing : target host의 dns 패킷을 가로채 특정 웹사이트로 접속을 유도한다.

  5. DrDOS : target host에게 web server를 이용해 무수히 많은 웹페이지 요청 패킷을 보낸다.






                                                                      작성자 : 김영환
                                                                      연락처 : napoleon27y@gmail.com
