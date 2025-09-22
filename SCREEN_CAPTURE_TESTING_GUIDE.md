# Screen Capture Protection Testing Guide

## Overview
This guide provides comprehensive testing procedures for the screen capture protection system implemented in both Student and Merchant React Native apps.

## Prerequisites

### Required Dependencies Installation
Before testing, ensure all dependencies are installed:

```bash
# Install dependencies for both apps
cd apps/student && npm install
cd ../merchant && npm install

# Install additional required packages if not already present
npm install @react-native-async-storage/async-storage @react-native-community/netinfo
```

### Development Environment Setup
1. **Backend Server**: Ensure the backend is running on `http://localhost:5000`
2. **Device/Simulator Configuration**:
   - **iOS Simulator**: Use `localhost:5000`
   - **Android Emulator**: Use `10.0.2.2:5000`
   - **Physical Devices**: Use your computer's LAN IP address

## Platform-Specific Testing

### Android Testing

#### 1. FLAG_SECURE Protection Test
**Expected Behavior**: Screenshots and screen recordings should be blocked at OS level

**Test Steps**:
1. Launch the student/merchant app on Android device/emulator
2. Navigate to any screen within the app
3. Attempt to take a screenshot using:
   - Power + Volume Down buttons
   - Device's built-in screenshot gesture
   - Third-party screenshot apps
4. Attempt to start screen recording using:
   - Android's built-in screen recorder
   - Third-party screen recording apps

**Expected Results**:
- Screenshots should fail with system message "Can't take screenshot due to security policy"
- Screen recordings should show black screen for the app content
- App should log `prevented` events to the backend
- Console should show "Android screen capture prevented" message

#### 2. Fallback Behavior Test
**Test Steps**:
1. Temporarily disable `preventScreenCaptureAsync` in code
2. Launch app and attempt screenshot/recording
3. Verify blur overlay appears when security API fails

**Expected Results**:
- Blur overlay should appear covering app content
- `fallback_displayed` event should be logged to backend

### iOS Testing

#### 1. Screenshot Detection Test
**Expected Behavior**: Screenshots should be detected and logged, with brief blur overlay

**Test Steps**:
1. Launch the student/merchant app on iOS device/simulator
2. Navigate to any screen within the app
3. Take a screenshot using:
   - Home + Power buttons (older devices)
   - Volume Up + Side button (newer devices)
   - AssistiveTouch screenshot

**Expected Results**:
- Screenshot should complete normally (iOS doesn't allow blocking)
- Brief blur overlay should appear for ~1 second
- `screenshot` event should be logged to backend
- `fallback_displayed` event should be logged

#### 2. Screen Recording Detection Test
**Expected Behavior**: Screen recording should be detected with persistent blur overlay

**Test Steps**:
1. Start screen recording from Control Center
2. Launch the student/merchant app
3. Navigate through different screens
4. Stop screen recording

**Expected Results**:
- Blur overlay should appear when recording starts
- `recording_start` event should be logged
- `fallback_displayed` event should be logged
- Overlay should disappear when recording stops
- `recording_stop` event should be logged

## Security Event Logging Tests

### 1. Event Logging Verification
**Test Steps**:
1. Monitor backend logs: `tail -f server/logs/security_events.log`
2. Perform various security actions on mobile apps
3. Check database for logged events:
   ```sql
   SELECT * FROM security_events ORDER BY created_at DESC LIMIT 10;
   ```

**Expected Event Types**:
- `prevented` - Android FLAG_SECURE activated
- `screenshot` - iOS screenshot detected
- `recording_start` - iOS screen recording started
- `recording_stop` - iOS screen recording stopped
- `fallback_displayed` - Blur overlay shown

### 2. Rate Limiting Test
**Test Steps**:
1. Take 5 screenshots rapidly in succession
2. Check logs for rate limiting behavior

**Expected Results**:
- Only 1 event per type should be logged per 15-second window
- Console should show "Security event rate limited" messages

### 3. Offline Queue Test
**Test Steps**:
1. Disconnect device from internet
2. Perform screenshot/recording actions
3. Reconnect to internet
4. Wait for queue processing

**Expected Results**:
- Events should be queued locally when offline
- Events should be sent to backend when connectivity resumes
- Exponential backoff should be applied for failed retries

## Per-Screen Override Testing

### 1. useSecureScreen Hook Test
**Test Implementation**:
Add to any screen component:
```tsx
import { useSecureScreen } from '../security';

const MyScreen = () => {
  const { isObscured, isEnabled, enable, disable } = useSecureScreen({
    screenName: 'MyScreen',
    enabled: true
  });

  return (
    <View>
      <Text>Security Enabled: {isEnabled.toString()}</Text>
      <Text>Content Obscured: {isObscured.toString()}</Text>
      <Button title="Disable Security" onPress={disable} />
      <Button title="Enable Security" onPress={enable} />
    </View>
  );
};
```

**Test Steps**:
1. Navigate to screen with useSecureScreen implementation
2. Test enable/disable functionality
3. Verify security behavior changes per screen

**Expected Results**:
- Android should toggle FLAG_SECURE on/off
- iOS should show/hide blur overlay based on screen settings
- `screen_changed` events should be logged

### 2. Navigation Integration Test
**Test Steps**:
1. Navigate between different screens
2. Configure different security settings per screen
3. Verify security behavior persists per screen

## Performance Testing

### 1. App Startup Impact
**Test Steps**:
1. Measure app startup time with security enabled
2. Measure app startup time with security disabled
3. Compare performance impact

**Acceptance Criteria**:
- Security system should add <200ms to startup time
- No memory leaks from event listeners
- Smooth navigation between screens

### 2. Battery Impact Test
**Test Steps**:
1. Monitor battery usage during extended app use
2. Compare with security system disabled

**Acceptance Criteria**:
- Minimal battery impact (<2% increase)
- No excessive background processing

## Error Handling Tests

### 1. API Failure Test
**Test Steps**:
1. Temporarily disable backend server
2. Perform security actions
3. Restart backend server

**Expected Results**:
- Events should queue locally when API unavailable
- Events should flush when API becomes available
- No app crashes or errors

### 2. Permission Denied Test
**Test Steps**:
1. Test on device/OS versions that might deny screen capture permissions
2. Verify graceful fallback to blur overlay

## Web Platform Testing (if applicable)

### 1. Platform Detection Test
**Test Steps**:
1. Run app in web browser
2. Verify security system doesn't break web functionality

**Expected Results**:
- No native API calls on web platform
- Security events still logged for web interactions
- No runtime errors or crashes

## Automated Testing Scripts

### Backend API Test
```bash
# Test security event logging endpoint
curl -X POST http://localhost:5000/api/security/screencap-attempt \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "screenshot",
    "platform": "ios",
    "app_version": "1.0.0",
    "screen_name": "test_screen",
    "session_id": "test_session"
  }'
```

### Device Information Verification
Add temporary logging to verify device info collection:
```tsx
console.log('Device Info:', {
  platform: Platform.OS,
  appVersion: Application.nativeApplicationVersion,
  buildNumber: Application.nativeBuildVersion,
  osVersion: Platform.Version,
  deviceModel: Device.modelName
});
```

## Test Results Checklist

### Android Tests
- [ ] FLAG_SECURE prevents screenshots
- [ ] FLAG_SECURE prevents screen recording
- [ ] `prevented` events logged correctly
- [ ] Fallback blur overlay works when API fails
- [ ] Per-screen overrides toggle FLAG_SECURE
- [ ] Rate limiting works correctly
- [ ] Offline queueing and retry logic functional

### iOS Tests  
- [ ] Screenshot detection works
- [ ] Screen recording detection works
- [ ] Brief blur overlay on screenshot
- [ ] Persistent blur overlay during recording
- [ ] All event types logged correctly
- [ ] Per-screen override behavior functional
- [ ] Rate limiting works correctly
- [ ] Offline queueing and retry logic functional

### Cross-Platform Tests
- [ ] Backend API receives events from both platforms
- [ ] Database stores events correctly
- [ ] Event payload validation works
- [ ] Device information collected accurately
- [ ] Session tracking works correctly
- [ ] Performance impact acceptable
- [ ] Error handling graceful

## Troubleshooting

### Common Issues
1. **Events not reaching backend**: Check API base URL configuration
2. **Android protection not working**: Verify FLAG_SECURE API availability
3. **iOS detection not working**: Check Expo SDK version compatibility
4. **Offline queue not working**: Verify AsyncStorage and NetInfo installation

### Debug Logging
Enable verbose logging for troubleshooting:
```tsx
console.log('Security Event:', eventData);
console.log('Queue Status:', eventQueue.length);
console.log('Network Status:', isOnline);
```

## Production Readiness Checklist

- [ ] All tests passing on both platforms
- [ ] API base URL configured for production environment
- [ ] Error monitoring set up for security events
- [ ] Performance impact documented and acceptable
- [ ] Privacy policy updated to mention screen capture protection
- [ ] User education about security features provided

## Next Steps for Production

1. **Environment Configuration**: Externalize API URLs via app.json
2. **Navigation Integration**: Add automatic screen change detection
3. **Analytics Integration**: Connect to analytics platform for security metrics
4. **User Settings**: Add toggle for users to control security preferences
5. **Compliance Documentation**: Document security measures for app store reviews