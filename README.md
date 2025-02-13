A Go utility for analyzing URL patterns and generating regex matches from URL lists. Designed to help identify unique URL structures while filtering out static resources.

```
go install github.com/0xQRx/URLDedup/cmd/urldedup@latest

urldedup -f urls.txt -ignore "css,js,png,jpg,jpeg,gif,svg"
```