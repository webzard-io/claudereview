# Image Support Test

## Test Cases

### 1. Claude Code Session with Image

**Input JSONL:**
```jsonl
{"type":"user","message":{"role":"user","content":[
  {"type":"text","text":"Here is a screenshot"},
  {"type":"image","source":{"type":"base64","media_type":"image/png","data":"..."}}
]}}
```

**Expected Output:**
- Text message: "Here is a screenshot"
- Image displayed below the text
- Image container with border and rounded corners
- Image scales to fit container (max 600px height)

### 2. Gemini CLI Session with Image

**Input JSON:**
```json
{
  "messages": [
    {
      "role": "user",
      "parts": [
        {"text": "Look at this"},
        {"inlineData": {"mimeType": "image/jpeg", "data": "..."}}
      ]
    }
  ]
}
```

**Expected Output:**
- Text message: "Look at this"
- Image displayed as separate message
- Same styling as Claude Code images

### 3. Multiple Images in One Message

**Expected Behavior:**
- Each image creates a separate message
- Images are displayed in order
- Text and images are properly separated

## Visual Verification

1. Generate preview: `bun run cli preview <session-id>`
2. Open HTML in browser
3. Verify:
   - ✓ Images load correctly
   - ✓ Images are responsive
   - ✓ Images have proper borders and styling
   - ✓ Lazy loading works (check network tab)
   - ✓ Images work in both light and dark themes

## Supported Image Formats

- PNG (image/png)
- JPEG (image/jpeg)
- GIF (image/gif)
- WebP (image/webp)
- SVG (image/svg+xml)

## Limitations

- Images must be base64 encoded
- Gemini `fileData` (URI references) show placeholder text only
- Maximum recommended image size: 5MB (base64 encoded)
