# Image Support

claudereview 现在支持在分享的 session 中显示图片。

## 支持的格式

### Claude Code Sessions

Claude Code 会话中的图片格式：

```jsonl
{
  "type": "user",
  "message": {
    "role": "user",
    "content": [
      {
        "type": "text",
        "text": "这是一张截图"
      },
      {
        "type": "image",
        "source": {
          "type": "base64",
          "media_type": "image/png",
          "data": "iVBORw0KGgo..."
        }
      }
    ]
  }
}
```

### Gemini CLI Sessions

Gemini CLI 会话中的图片格式：

```json
{
  "messages": [
    {
      "role": "user",
      "parts": [
        {
          "text": "看这张图"
        },
        {
          "inlineData": {
            "mimeType": "image/jpeg",
            "data": "base64_encoded_data..."
          }
        }
      ]
    }
  ]
}
```

## 功能特性

- ✅ 支持所有常见图片格式（PNG, JPEG, GIF, WebP, SVG）
- ✅ 响应式设计，自动适配容器宽度
- ✅ 最大高度限制为 600px，保持纵横比
- ✅ 懒加载优化性能
- ✅ 深色/浅色主题适配
- ✅ 图片边框和圆角样式
- ✅ 加密分享中也支持图片

## 样式

图片会被渲染在一个带有以下样式的容器中：

- 圆角边框（8px）
- 边框颜色适配主题
- 背景色为次要背景色
- 图片居中显示
- 自动缩放以适应容器

## 限制

- 图片必须是 base64 编码
- Gemini 的 `fileData`（URI 引用）只显示占位符文本
- 建议图片大小不超过 5MB（base64 编码后）

## 示例

查看包含图片的实际 session：

```bash
# 预览包含图片的 session
bun run cli preview <session-id>

# 上传并分享
bun run cli upload <session-id>
```

## 技术实现

1. **Parser 层**：从 JSONL/JSON 中提取图片数据
2. **Types 层**：扩展类型定义支持图片消息
3. **Renderer 层**：生成带有 base64 data URI 的 `<img>` 标签
4. **CSS 层**：提供响应式图片容器样式

图片数据完全嵌入在 HTML 中，无需外部资源，确保分享链接的自包含性。
