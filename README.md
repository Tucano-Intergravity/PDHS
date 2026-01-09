# E3T - IGNU Payload Communication Tester

이 프로그램은 E3T 위성과 IGNU 탑재체(InterGravity) 간의 통신을 테스트하기 위한 Python 기반 GUI 도구입니다.
`E3T-SP-400-003 R06.5` 및 `IGNU-SW-ICD-001` 문서를 준수하여 작성되었습니다.

## 주요 변경 사항 (ICD 적용)

*   **프로토콜 스택**: RS-422 > KISS > CSP > SPP 적용
*   **Endianness**: 
    *   Headers: Big Endian
    *   User Data Field: Little Endian (IGNU ICD 준수)
*   **기능 추가**: 
    *   Start/Stop Test 명령
    *   Status Request (HK) 명령
    *   시험 데이터 텔레메트리 (95 bytes) 파싱 및 실시간 표시

## 실행 방법

### 1. 환경 설정

Python이 설치되어 있어야 합니다. 필요한 라이브러리를 설치하세요:

```bash
pip install -r requirements.txt
```

### 2. 가상 시리얼 포트 설정 (테스트 시)

하드웨어가 없는 경우, 가상 시리얼 포트 쌍을 생성하여 테스트할 수 있습니다.
*   **Windows**: `com0com` 등을 사용하여 COM 포트 쌍 생성 (예: COM1 <-> COM2).
*   이 프로그램에서 COM1을 연결하고, 다른 터미널 프로그램이나 에뮬레이터를 COM2에 연결하세요.

### 3. 프로그램 실행

```bash
python main.py
```

## 주의사항

*   CSP 주소(`SOURCE_ADDRESS`, `DEST_ADDRESS`) 및 포트는 실제 할당표(Table 1 등)에 따라 `main.py` 상단의 상수를 수정해야 합니다. 현재는 임의의 값(10, 20)이 설정되어 있습니다.
*   텔레메트리 파싱은 `IGNU-SW-ICD-001`의 Table 5 구조를 따릅니다.
