# Changelog

## [Unreleased]

### Added
- **Image support in sessions**: Sessions can now display images uploaded by users
  - Claude Code sessions: Supports `type: "image"` content blocks with base64 encoded images
  - Gemini CLI sessions: Supports `inlineData` image parts with base64 encoded images
  - Images are rendered inline with proper styling and lazy loading
  - Maximum image height: 600px with automatic scaling to fit container
  - Supports all common image formats (PNG, JPEG, GIF, WebP, etc.)

### Technical Details
- Added `image` type to `ParsedMessage` and `MessagePart` interfaces
- Extended `ContentBlock` to support image source data
- Parser now extracts image blocks from user messages
- Renderer generates responsive image containers with proper styling
- Images are embedded as base64 data URIs for self-contained HTML output
