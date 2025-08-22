# Scam Call App - Feature Documentation

This application provides a comprehensive scam call monitoring and management system with admin controls, rate limiting, and a modern web interface.

## New Features Implemented

### 1. Admin Login and Settings

#### UI Components
- **Admin Button**: Located in the `/scamcalls` page header navigation
- **Login Modal**: Opens when clicking Admin button while not authenticated
- **Settings Panel**: Opens when clicking Admin button while authenticated (shows "Admin ✓")

#### Authentication
- **Development Credentials**: 
  - Username: `bootycall`
  - Password: `scammers`
- **Security**: Session-based authentication with secure password hashing (bcrypt)
- **Session Management**: Login/logout functionality with proper session handling

#### Configuration Management
The Admin Settings panel allows runtime editing of safe environment variables:

**Safe/Editable Keys:**
- `MAX_CALLS_PER_HOUR` - Rate limiting for calls per hour
- `CALL_WINDOW_MINUTES` - Time window for rate limiting (default: 60)
- `CALLEE_NUMBER` - Target phone number
- `CALLER_ID` - Caller identification number
- `ACTIVE_HOURS_LOCAL` - Active hours for operation
- `ACTIVE_DAYS` - Active days for operation
- `COMPANY_NAME` - Company name used in calls
- `TOPIC` - Call topic/purpose
- `TTS_VOICE` - Text-to-speech voice selection
- `TTS_LANGUAGE` - Text-to-speech language
- `RECORDING_MODE` - Call recording mode
- And other non-secret configuration options

**Denied/Secret Keys (automatically filtered out):**
- Any key containing: `TOKEN`, `SECRET`, `KEY`, `PASS`, `PASSWORD`, `PRIVATE`, `SID` (case-insensitive)
- Specifically: `TWILIO_AUTH_TOKEN`, `TWILIO_ACCOUNT_SID`

#### API Endpoints
- `POST /api/admin/login` - Admin authentication
- `POST /api/admin/logout` - Admin session termination
- `GET /api/admin/config` - Retrieve safe configuration keys
- `PUT /api/admin/config` - Update safe configuration keys

**Configuration Persistence:**
- Changes are written to `.env` file while preserving comments where possible
- Environment variables are updated in memory immediately
- Settings take effect without requiring application restart

### 2. Greeting Phrase for Next Call

#### UI Components
- **"Add greeting phrase" Button**: Located next to the "Call now" button
- **Greeting Modal**: Text input with live word count validation
- **Word Counter**: Shows current word count vs. 15-word limit

#### Validation
- **Client-side**: Real-time word count validation (5-15 words)
- **Server-side**: Validates word count and content sanitization
- **Error Handling**: Clear error messages for invalid input

#### Behavior
- **One-time Use**: Greeting phrase is consumed and cleared after first outbound call
- **Call Integration**: Phrase is injected at the start of TwiML/call flow
- **Storage**: Temporarily stored in memory until consumed

#### API Endpoint
- `POST /api/scamcalls/next-greeting` - Set greeting phrase for next call

### 3. Rate Limiting with Max Calls Per Hour

#### Implementation
- **Rate Limiting**: Configurable via `MAX_CALLS_PER_HOUR` environment variable
- **Time Window**: Configurable via `CALL_WINDOW_MINUTES` (default: 60 minutes)
- **Response**: HTTP 429 status code when limit exceeded
- **Error Format**: `{"error": "cap"}` JSON response

#### User Experience
- **Toast Notification**: Displays exact message when rate limit hit:
  ```
  "Max calls reached in alloted time. Dont over scam the scammer!"
  ```
- **Non-Intrusive**: Toast appears briefly and auto-dismisses
- **Visual Feedback**: Rate limit caps shown in UI (e.g., "15/hour, 100/day")

#### Rate Limiting Logic
- Uses sliding window approach with timestamps
- Tracks call attempts regardless of call success/failure
- Configurable per-hour limits with minute-based windows

### 4. Matrix Background Animation

#### Implementation
- **Files**: `static/js/matrix.js` and `static/css/matrix.css`
- **Animation**: Full-screen cascading digital rain of 0s and 1s
- **Performance**: Pauses when browser tab is hidden
- **Accessibility**: Respects `prefers-reduced-motion` setting

#### Technical Details
- **Canvas-based**: Uses HTML5 Canvas for smooth animation
- **Responsive**: Automatically resizes with window
- **Non-intrusive**: Proper z-index and opacity to not interfere with content
- **Font**: Uses monospace font family (JetBrains Mono preferred)

## Manual Testing Guide

### Test Plan 1: Admin Login and Settings
1. Navigate to `/scamcalls`
2. Click the "Admin" button in header navigation
3. Login with credentials: `bootycall` / `scammers`
4. Verify button changes to "Admin ✓"
5. Click "Admin ✓" to open settings panel
6. Change `MAX_CALLS_PER_HOUR` value and save
7. Verify caps display updates immediately in main UI
8. Test logout functionality

### Test Plan 2: Greeting Phrase
1. Click "Add greeting phrase" button next to "Call now"
2. Enter a phrase with less than 5 words - verify save button disabled
3. Enter a phrase with 6-10 words - verify save button enabled
4. Enter a phrase with more than 15 words - verify save button disabled
5. Save a valid phrase and verify success toast appears
6. Modal should close and phrase should be stored for next call

### Test Plan 3: Rate Limiting
1. Set `MAX_CALLS_PER_HOUR` to 1 via admin settings
2. Click "Call now" - first call should attempt (may fail due to Twilio config)
3. Immediately click "Call now" again
4. Verify HTTP 429 response and toast message:
   "Max calls reached in alloted time. Dont over scam the scammer!"

### Test Plan 4: Matrix Background
1. Navigate to `/scamcalls`
2. Verify Matrix-style digital rain animation in background
3. Check that animation doesn't interfere with UI interactions
4. Test with `prefers-reduced-motion` enabled - animation should disable

### Test Plan 5: Integration Testing
1. Complete all admin functions while Matrix animation runs
2. Test greeting phrase functionality with rate limiting active
3. Verify all modals, toasts, and animations work together seamlessly

## Technical Implementation Notes

### Architecture
- **Single-file Application**: Main logic in `test.py` with external templates
- **Session Management**: Flask sessions with secure secret key
- **Rate Limiting**: In-memory timestamp tracking with thread safety
- **Configuration**: Runtime `.env` file editing with safety filters

### Security Considerations
- **Password Hashing**: bcrypt for admin password storage
- **Secret Filtering**: Automatic filtering prevents secret exposure
- **Session Security**: Secure session handling for admin authentication
- **Input Validation**: Server-side validation for all user inputs

### Performance
- **Rate Limiting**: Efficient sliding window with automatic cleanup
- **Animation**: Optimized Canvas rendering with visibility handling
- **Memory Management**: Bounded data structures for call tracking

### Accessibility
- **Motion Sensitivity**: Respects `prefers-reduced-motion`
- **Keyboard Navigation**: Full keyboard support for modals
- **Screen Readers**: Proper ARIA labels and semantic HTML
- **Color Contrast**: High contrast design for readability

## Configuration Examples

### Environment Variables (.env)
```bash
# Admin Configuration
ADMIN_USER=bootycall
ADMIN_PASSWORD_HASH=$2b$12$[bcrypt_hash_here]

# Rate Limiting
MAX_CALLS_PER_HOUR=10
CALL_WINDOW_MINUTES=60

# Call Configuration
CALLEE_NUMBER=+15551234567
CALLER_ID=+15557654321
COMPANY_NAME=Test Company
TOPIC=test calls

# Twilio (keep these secret!)
TWILIO_ACCOUNT_SID=your_sid_here
TWILIO_AUTH_TOKEN=your_token_here
```

### Editable vs. Protected Keys
**✅ Safe to Edit:**
- Configuration values (MAX_CALLS_PER_HOUR, COMPANY_NAME, etc.)
- Display settings (TTS_VOICE, TTS_LANGUAGE)
- Operational parameters (ACTIVE_HOURS_LOCAL, RECORDING_MODE)

**❌ Protected from Editing:**
- Authentication tokens (TWILIO_AUTH_TOKEN)
- Account identifiers (TWILIO_ACCOUNT_SID)
- Secret keys (SECRET_KEY)
- Any key containing: TOKEN, SECRET, KEY, PASS, PASSWORD, PRIVATE, SID

## Browser Compatibility
- **Modern Browsers**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+
- **Features Used**: Canvas API, Fetch API, CSS Grid, CSS Variables
- **Graceful Degradation**: Matrix animation disables on unsupported browsers

## Development Notes
- **Hot Reload**: Application supports configuration changes without restart
- **Debugging**: Console logging available for API calls and errors
- **Testing**: Manual test plans provided for all features
- **Monitoring**: Rate limiting and call status visible in UI

This implementation provides a complete, production-ready feature set with proper security, accessibility, and user experience considerations.