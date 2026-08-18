---
title: "[예시] 웹 취약점 분석 글 작성법"
published: 2026-08-19
description: "로컬 실습 환경에서 발견한 접근 제어 취약점을 분석하고 재현 과정을 정리하는 예시입니다."
image: ""
tags: ["Web Security", "Access Control", "Write-up"]
category: "Vulnerability Research"
draft: true
---

## 개요

이 글은 웹 취약점 분석 기록을 어떤 순서로 작성할 수 있는지 보여주기 위한 예시입니다.
테스트 대상은 외부 서비스가 아닌 로컬 실습 환경이며, 사용자 A와 사용자 B가 각각
자신의 메모를 관리할 수 있다고 가정합니다.

> [!NOTE]
> 실제 서비스를 테스트할 때는 프로그램의 허용 범위와 테스트 정책을 먼저 확인해야 합니다.

## 테스트 환경

| 항목 | 내용 |
|---|---|
| 대상 | `https://lab.example.test` |
| 기능 | 개인 메모 조회 |
| 테스트 계정 | 사용자 A, 사용자 B |
| 요청 방식 | HTTP `GET` |
| 기대 경계 | 자신의 메모만 조회 가능 |

## 발견 내용

메모 조회 요청의 `noteId` 값을 다른 사용자가 소유한 메모 ID로 변경했을 때,
서버가 메모 소유자를 확인하지 않고 내용을 반환했습니다.

정상적인 요청은 다음과 같습니다.

```http
GET /api/notes/1001 HTTP/1.1
Host: lab.example.test
Authorization: Bearer [USER_A_TOKEN]
Accept: application/json
```

```json
{
  "id": 1001,
  "owner": "user-a",
  "title": "User A note"
}
```

`noteId`만 사용자 B의 메모 ID로 변경한 요청은 다음과 같습니다.

```http
GET /api/notes/2001 HTTP/1.1
Host: lab.example.test
Authorization: Bearer [USER_A_TOKEN]
Accept: application/json
```

서버는 접근을 거부하지 않고 사용자 B의 메모를 반환했습니다.

```json
{
  "id": 2001,
  "owner": "user-b",
  "title": "User B note"
}
```

## 재현 순서

1. 사용자 A로 로그인합니다.
2. 사용자 A가 소유한 메모를 열고 조회 요청을 확인합니다.
3. 별도의 사용자 B 계정으로 테스트용 메모를 하나 생성합니다.
4. 사용자 A의 인증 정보는 유지한 채 요청 경로의 `noteId`를 사용자 B의 메모 ID로 변경합니다.
5. 응답에 사용자 B의 테스트용 메모가 반환되는지 확인합니다.

## 실제 결과와 기대 결과

| 구분 | 결과 |
|---|---|
| 실제 결과 | 사용자 A가 사용자 B의 테스트용 메모를 조회할 수 있음 |
| 기대 결과 | 서버가 소유권 불일치를 확인하고 `403 Forbidden` 또는 `404 Not Found`를 반환해야 함 |

## 원인 분석

서버는 요청자가 인증된 사용자인지만 검사하고, 요청한 메모의 `ownerId`가 현재 사용자의
ID와 일치하는지는 검사하지 않았습니다. 즉, 객체를 조회하기 전에 객체 단위 접근 제어가
적용되지 않은 것이 원인입니다.

취약한 로직을 단순화하면 다음과 같습니다.

```ts
const note = await notes.findById(request.params.noteId);
return response.json(note);
```

소유권 조건을 함께 검사하도록 변경해야 합니다.

```ts
const note = await notes.findOne({
  id: request.params.noteId,
  ownerId: session.user.id,
});

if (!note) {
  return response.status(404).end();
}

return response.json(note);
```

## 영향

공격자가 다른 사용자의 메모 ID를 알 수 있다면 해당 메모를 조회할 수 있습니다. 다만 이
예시에서는 두 개의 사용자 소유 테스트 계정과 테스트 데이터만 사용했으므로, 실제 사용자
데이터에 대한 접근 가능성이나 전체 노출 규모는 확인하지 않았습니다.

## 대응 방안

- 모든 객체 조회에서 현재 사용자의 소유권 또는 역할을 서버 측에서 확인합니다.
- 목록, 상세 조회, 수정, 삭제 API에 동일한 접근 제어 정책을 적용합니다.
- 다른 사용자의 객체 ID를 사용했을 때 접근이 거부되는 회귀 테스트를 추가합니다.

## 정리

취약점 분석 글에는 단순히 “다른 데이터가 보였다”는 결론만 적기보다 정상 요청과 변형
요청, 실제·기대 결과, 보안 경계가 실패한 원인을 함께 기록하는 것이 좋습니다. 검증 범위를
명확히 적으면 확인한 사실과 추정한 영향을 구분하는 데에도 도움이 됩니다.
