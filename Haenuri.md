# Haenuri - Design Project 1

## 주어진 상황
### 피해 사항
- radiation에 의한 피해는 없음
- solar wind에 의한 피해가 발생

### 요구 조건
- Probe의 safe operation
    - 현재 solar wind에 노출된 메모리 쓰면 안됌 (아니면 터짐)
    - solar wind에 더 이상 노출되지 않는 RAM 부분을 다시 쓸 수는 있지만 data corruption 발생
- mitigate speed loss from damage --> feedback system?
    - 디자인을 적용함으로써 발생하는 speed loss를 최소화

### 하드웨어 사양
- RAM 1 (Userspace) : Pintos의 User Pool에 대응되는 일부, 손상 가능한 부분
- RAM 2 (Userspace, SuperFastRAM) : Pintos의 User Pool을 구성하는 일부, 항상 안전
- RAM 3 (Kernelspace) : Pintos의 Kernel Pool에 대응, 항상 안전

정리하자면, <b>Kernel 영역은 항상 안전하다</b>.

### 세부 문제 상황
- 손상 예상 알고리즘 : 30틱 앞(한치 앞)의 태양풍에 의한 손상 영역 예측
- 태양풍은 30틱마다 변화하며, 동시에 최대 14개 Frame 손상 가능
- Frame 1개 읽고 쓸 때마다 0.1틱 소모
- Frame 1개 디스크에 읽고 쓸 때마다 1틱 소모
- Phys.Mem. 크기 2000 frame
- Super Fast Ram 크기 10 frame

## 해야 하는 것
### 기본 구조
1. 미래 예측값 불러오고, <b>손상될 영역 / 복원할 영역을 예상, 시간 할당</b>(안전을 위해 1 tick의 여유를 두자), 그리고 그 시간을 t_pre 라고 하자
2. 태양풍 변화로부터 t_pre 전에는, 모든 스레드를 멈추고 커널 코드를 실행, 백업한다.
3. 반복한다.

### 주요 조건
- 10개까지는 Super Fast Ram이라는 "딸깍"으로 해결 가능
- 4개는 남는 UserSpace Frame, 혹은 디스크 사용 필요
- 백업한(뒤질) 프레임에 대해서는 Page Table 조작으로 '옮긴 위치'로 바꿔준다.

## 디자인 과정
### 1. 초안 - 복사본 15개씩 램에 꼴아박기 -> Workload 문제, PageTable 문제
### 2. 개선안 - 정확히 피해서 램에 4개씩만 박기 -> Workload 문제
### 3. 2차 개선안 - 4개 다 디스크에 박기 -> 성능이 꼴아박음
### 4. 3차 개선안 - 4개를 기본적으로 램에 박되 없으면 디스크

### 공통 문제점 : 백업하는 시점에, 이전 백업본을 복원할 수 없음
- 기본적으로는 SFRAM > RAM > DISK 순으로 백업을 하며, 전부 차있을 때만 아래 단계로
- 복원 직전에는 백업본이 2개(총 28개 프레임까지 가능) 있음에 유의

#### Worst Case : 항상 User RAM이 꽉 차있다고 해보자.
- 1번째 백업 : 10 Frames(SFRAM) + 4 Frames(DISK)
- 2번째 백업 : 14 Frames(DISK)

2번째 백업 생성 + 1번째 백업 복원 시간 = (14 * 1.1) + (10 * 0.1 + 4 * 1.1) = 20.8 tick

----

- 2번째 백업 : 14 Frames(DISK)
- 3번째 백업 : 10 Frames(SFRAM) + 4 Frames(DISK)

3번째 백업 생성 + 2번째 백업 복원 시간 = (10 * 0.1 + 4 * 1.1) + (14 * 1.1) = 20.8 tick

----

위 경우에서 n번째 백업의 생성 이전 n-1번째 백업 중에 k개 frame을 SFRAM으로 옮길 경우

n-1번째 백업 수정 시간 + n 번째 백업 생성 시간 + n-1번째 백업 복원 시간
= (k) + ((10 - k) * 0.1 + (4+k) * 1.1 ) + (k * 0.1 + (14 - k) * 1.1)
= {안할 경우} + k

따라서, 최악의 경우에는 위의 경우가 최선이다.

### 4차 개선안. 3차 개선안에 '백업 이후 복원'의 개념 추가
1. 기존 백업본이 있다면, 복원한다.
2. int[] disturbed_frame_indices_at(tick t) 활용, 미래 손상될 frame 확인
3. 백업에 필요한 시간 계산 (+여유 틱 부여?)
4. 백업, 이후 태양풍 변화, 반복

### 백업에 적극적으로 RAM 부여? -> 5차 개선안
램이 없을 때, 임의로 18 Frames를 Evict 해 버리고, 이를 백업 공간으로 사용하는 경우?
일단 Worst case의 성능 자체는 같은데, Userprog가 RAM을 특정 region만 쓴다고 하면, 이 경우가 더 나을 수는 있다. 
<b>백업은 30틱마다 무조건 있어야 하는 작업이기 때문</b>
다만, 로직은 매우 복잡해질 것이며, 해당 Evict를 통해 얻은 해당 공간이 안전한 공간이 아니게 되는 경우에 문제가 발생한다.

### Thrashing
백업된 것 중 디스크에 있는 것들을 SFRAM에 가져와서, SFRAM에 있던게 DISK로 간 상황에서 다시 DISK로 간 그 FRAME 요구 시(반복 참조)
-> USERPROG의 문제

### 백업용으로 할당된 RAM에 대한 손상
-> 비어있는 자리를 찾아 넣고, 없으면 USERPROG Evict해서 백업공간 확보