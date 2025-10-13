# 🚀 PhishNet - Quick GitHub Upload Commands

## Step-by-Step Commands

### 1️⃣ Check Current Status
```powershell
cd C:\Users\piyus\AppData\Local\Programs\Python\Python313\project\Phishnet
git status
```

### 2️⃣ Stage All Changes
```powershell
git add .
```

### 3️⃣ Commit Changes
```powershell
git commit -m "Add IMAP email integration with deployment configuration

- ThePhish-style IMAP forwarding workflow
- 4 REST API endpoints for email analysis
- Enhanced 5-module phishing analyzer
- Complete deployment documentation
- Real email testing (propam5553@gmail.com)
- Ready for Render and Vercel deployment"
```

### 4️⃣ Add GitHub Remote (if not added)
```powershell
git remote add origin https://github.com/MorePiyush55/Phishnet.git
```

If remote already exists, update it:
```powershell
git remote set-url origin https://github.com/MorePiyush55/Phishnet.git
```

### 5️⃣ Push to GitHub
```powershell
git push -u origin main
```

If you get an error, try force push (only if needed):
```powershell
git push -u origin main --force
```

---

## ✅ Verify Upload

1. Go to: https://github.com/MorePiyush55/Phishnet
2. Check if files are there
3. Verify latest commit message

---

## 🎯 Next: Deploy to Cloud

### Backend on Render:
1. Go to https://render.com
2. Click "New +" → "Web Service"
3. Connect GitHub: MorePiyush55/Phishnet
4. Root Directory: `backend`
5. Follow DEPLOYMENT_GUIDE.md

### Frontend on Vercel:
1. Go to https://vercel.com
2. Click "Add New..." → "Project"
3. Import: MorePiyush55/Phishnet
4. Root Directory: `frontend`
5. Follow DEPLOYMENT_GUIDE.md

---

## 🔒 Security Checklist Before Push

- [ ] Check `.gitignore` includes `.env` files
- [ ] No sensitive data in code
- [ ] All passwords removed from code
- [ ] App passwords stored separately

Check with:
```powershell
git ls-files backend/.env
git ls-files frontend/.env
```

If these show files, remove them:
```powershell
git rm --cached backend/.env
git rm --cached frontend/.env
git commit -m "Remove .env files from git"
```

---

## 📚 Full Documentation

See **DEPLOYMENT_GUIDE.md** for complete deployment instructions!
