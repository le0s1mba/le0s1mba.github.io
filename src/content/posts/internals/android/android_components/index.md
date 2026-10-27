---
title: "Android Components"
published: 2025-12-05
description: "Android Components에 대한 간략한 설명"
image: ""
tags: ["Android", "components", "internals"]
category: "Android"
draft: false
---

# 개요

Android에는 Activity, Service, Broadcast Receiver, Content Provider 이렇게 4개의 components가 존재한다.  
각 component마다 지정된 역할이 있으며, 각각의 component가 Android의 entry 역할을 한다.  
그럼 이제 각 component의 역할을 알아보자.  

# Components

## Activity

Activity component는 쉽게 말해서 하나의 UI 즉, 화면을 의미한다.  
이 Activity를 통해 user와 app이 통신할 수 있게 되며, 한 화면에는 하나의 Activity가 필요하다.  

## Service

흔히 말해 background에서 돌아가는 서비스다.  

## Broadcast Receiver

Android의 system과 app에서 보내지는 메시지를 수신하는 역할이다.  
background에서 돌아가며, 사용자가 정의해서 broadcast message를 보낼 수도 있다.  

## Content Provider

Content Provider가 속한 app에 외부에서 들어오는 데이터에 대한 CRUD 접근을 중간에 통제해 주는 역할이다.  