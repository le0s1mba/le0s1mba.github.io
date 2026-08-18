# le0s1mba.github.io

Fuwari와 Astro로 만든 개인 블로그입니다.

## 로컬 실행

```sh
corepack enable
pnpm install
pnpm dev
```

개발 서버는 기본적으로 `http://localhost:4321`에서 열립니다.

## 글 작성

```sh
pnpm new-post my-post
```

생성된 글은 `src/content/posts/`에서 편집합니다. 사이트 제목, 프로필, 메뉴는
`src/config.ts`에서 변경할 수 있습니다.

## 검사 및 빌드

```sh
pnpm check
pnpm build
```

`main` 브랜치에 푸시하면 GitHub Actions가 사이트를 빌드하여 GitHub Pages에
배포합니다. 저장소의 **Settings → Pages → Build and deployment → Source**가
**GitHub Actions**로 설정되어 있어야 합니다.

## Credits

Based on [Fuwari](https://github.com/saicaca/fuwari), licensed under the MIT License.
