# PhishNet Frontend - Vercel Deployment Guide

## Quick Deploy

### 1. Install Vercel CLI (if not already installed)
```bash
npm install -g vercel
```

### 2. Navigate to Frontend Directory
```bash
cd C:\Users\piyus\AppData\Local\Programs\Python\Python313\project\Phishnet\frontend
```

### 3. Deploy to Vercel
```bash
vercel --prod
```

Follow the prompts:
- **Set up and deploy**: Yes
- **Which scope**: Select your account
- **Link to existing project**: Yes (if you have one) or No (for new)
- **Project name**: phishnet-frontend
- **Directory**: `./` (current directory)

### 4. Configure Environment Variables

In the Vercel Dashboard (https://vercel.com):
1. Go to your project settings
2. Navigate to "Environment Variables"
3. Add the following:
   - **Name**: `BACKEND_URL`
   - **Value**: `https://phishnet-backend-iuoc.onrender.com`
   - **Environment**: Production

### 5. Redeploy (if needed)
```bash
vercel --prod
```

---

## Verify Deployment

### Test Checklist
1. ✅ Visit your Vercel URL
2. ✅ Verify landing page loads with premium design
3. ✅ Click "Get Started" button
4. ✅ Complete Google OAuth flow
5. ✅ Verify redirect to dashboard
6. ✅ Check browser console for errors

---

## Backend OAuth Configuration

### Update Backend Redirect URIs
Ensure your backend OAuth configuration includes your Vercel URL:

**Authorized redirect URIs**:
- `https://your-vercel-url.vercel.app/`
- `https://your-vercel-url.vercel.app/auth/callback`

Update in:
1. Google Cloud Console (OAuth 2.0 Client IDs)
2. Backend environment variables on Render

---

## Troubleshooting

### Issue: OAuth redirect fails
**Solution**: Verify backend redirect URI includes your Vercel URL

### Issue: 404 on dashboard redirect
**Solution**: Check that `vercel.json` rewrites are configured correctly

### Issue: Backend connection fails
**Solution**: Verify `BACKEND_URL` environment variable is set correctly

---

## Post-Deployment

### Update DNS (Optional)
If you have a custom domain:
1. Go to Vercel project settings
2. Navigate to "Domains"
3. Add your custom domain
4. Update DNS records as instructed

### Monitor Performance
- Check Vercel Analytics dashboard
- Monitor OAuth success rate
- Review error logs if any issues

---

## Files Deployed

The following files will be deployed to Vercel:
- `index.html` - Landing page
- `app.js` - Backend integration
- `vercel.json` - Configuration

**Excluded** (via `.vercelignore`):
- `node_modules/`
- `src.backup/`
- `.env` files
- Build artifacts

---

## Production URLs

After deployment, you'll have:
- **Landing Page**: `https://your-project.vercel.app/`
- **Dashboard**: `https://phishnet-tau.vercel.app/` (existing)
- **Backend**: `https://phishnet-backend-iuoc.onrender.com/`

---

## Support

If you encounter issues:
1. Check Vercel deployment logs
2. Verify backend is running on Render
3. Test OAuth flow manually
4. Review browser console for errors

---

**Ready to deploy!** 🚀
