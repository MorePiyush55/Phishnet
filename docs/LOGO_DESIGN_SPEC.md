# PhishNet Logo Design Specification

## Logo Concept Description

### Primary Logo Design
**Concept**: Shield-Net Protection Symbol

**Visual Elements**:
- **Central Shield**: Blue gradient shield (protection/security)
- **Net Pattern**: Overlaid mesh/net pattern in lighter blue
- **Email Symbol**: Small envelope icon integrated into shield
- **Phishing Hook**: Subtle crossed-out hook symbol (anti-phishing)

### Color Scheme
**Primary Colors**:
- **Security Blue**: #2E86AB (trust, reliability)
- **Accent Blue**: #A23B72 (analysis, intelligence)  
- **Background**: White or transparent
- **Text**: #2C3E50 (professional dark gray)

### Typography
**Primary Font**: Inter or Roboto (clean, modern)
**Logo Text**: "PhishNet" (when text needed)
**Tagline**: "Email Security Scanner" (when space allows)

## Logo Variations Needed

### 1. Full Logo (Recommended for OAuth)
- **Size**: 1024x1024px (high resolution)
- **Format**: PNG with transparent background
- **Usage**: Google OAuth Console, app store listings
- **Elements**: Shield + net pattern + "PhishNet" text

### 2. Icon Only (Minimum Required)
- **Size**: 120x120px minimum
- **Format**: PNG with transparent background
- **Usage**: Browser favicons, small UI elements
- **Elements**: Shield + net pattern only

### 3. Horizontal Logo
- **Usage**: Website headers, documentation
- **Elements**: Icon + "PhishNet Email Security Scanner" text
- **Dimensions**: 300x100px (approx 3:1 ratio)

## Design Guidelines

### Shield Design:
```
┌─────────────┐
│    ╭─╮     │  <- Shield outline (security)
│   ╱   ╲    │
│  ╱ ### ╲   │  <- Net/mesh pattern inside
│ ╱  ###  ╲  │
│╱   ###   ╲ │
│     📧     │  <- Small email icon
└─────────────┘
```

### Mesh Pattern Details:
- Hexagonal or diamond pattern
- Semi-transparent overlay
- Represents "net" catching threats
- Should not obscure main shield shape

### Integration Elements:
- Small email envelope (📧) centered in shield
- Optional: Crossed-out hook (🎣❌) for anti-phishing
- Gradient from dark blue (top) to lighter blue (bottom)

## Creating the Logo

### Option 1: Design Tools
**Recommended Tools**:
- Figma (free, web-based)
- Canva (templates available)
- Adobe Illustrator (professional)
- GIMP (free alternative)

### Option 2: AI Generation
**Prompts for AI Logo Generators**:
```
"Create a professional logo for PhishNet email security scanner. 
Blue shield with mesh net pattern overlay, small email envelope icon, 
modern tech company style, 1024x1024 pixels, transparent background"
```

### Option 3: Simple Icon Fonts
**Using Icon Libraries**:
- Font Awesome: shield-alt + envelope
- Material Icons: security + email
- Combine with CSS styling for blue colors

## Logo Implementation

### 1. File Structure
```
static/images/logos/
├── phishnet-logo-1024.png    # High resolution (OAuth Console)
├── phishnet-logo-120.png     # Minimum required size
├── phishnet-icon-32.png      # Favicon
├── phishnet-horizontal.png   # Header logo
└── phishnet-square.svg       # Scalable vector version
```

### 2. Favicon Integration
**HTML Head Section**:
```html
<link rel="icon" type="image/png" sizes="32x32" href="/static/images/logos/phishnet-icon-32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/static/images/logos/phishnet-icon-16.png">
<link rel="apple-touch-icon" sizes="180x180" href="/static/images/logos/phishnet-icon-180.png">
```

### 3. OAuth Console Upload
**Required Specifications**:
- Format: PNG or JPG
- Minimum: 120x120 pixels
- Recommended: 1024x1024 pixels
- Background: Transparent preferred
- File size: Under 1MB

## Brand Guidelines

### Logo Usage Do's:
- Use on white or light backgrounds for visibility
- Maintain aspect ratio when resizing
- Use official color scheme
- Include adequate white space around logo
- Use high-resolution versions for print/large displays

### Logo Usage Don'ts:
- Don't stretch or distort proportions
- Don't use low-resolution versions for large displays
- Don't change colors significantly
- Don't add drop shadows or effects
- Don't place on busy backgrounds that reduce visibility

## Quick Implementation Guide

### Temporary Logo Creation (for immediate use):
1. **Use Icon Fonts**: Combine 🛡️ and 📧 emojis with CSS styling
2. **Text-Based**: "PN" letters in blue circle with shield border
3. **Simple Geometric**: Blue circle with white envelope and mesh pattern

### Professional Logo Creation (recommended):
1. Hire designer on Fiverr/99designs ($25-100)
2. Use AI generators (Midjourney, DALL-E) with specific prompts
3. Create in design tool following specifications above

## Testing Logo

### Visibility Tests:
- [ ] Clear at 16x16 pixels (favicon size)
- [ ] Readable at 32x32 pixels (small UI elements)
- [ ] Professional at 120x120 pixels (OAuth minimum)
- [ ] Crisp at 1024x1024 pixels (high resolution)

### Context Tests:
- [ ] Looks professional in OAuth consent screen
- [ ] Fits well in browser tab
- [ ] Clear in email signatures
- [ ] Appropriate for business communications

---

**Status**: Logo specification complete
**Next Step**: Create actual logo files and implement in application
**Priority**: Medium (required for professional OAuth verification)