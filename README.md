# security-alert

แจ้งข่าวช่องโหว่ร้ายแรงเข้า Discord ภายในไม่กี่นาที ทุกข้อความบอกประเภทการโจมตี ช่องทางโจมตี วิธีแก้ และลิงก์

## แจ้งอะไรบ้าง

| การ์ด | แหล่งข่าว | แจ้งเมื่อ |
|---|---|---|
| 🚨 ถูกโจมตีจริง (ping `@here`) | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | มีรายการใหม่ ทุกรายการ |
| Open-source critical | [GitHub Advisory](https://github.com/advisories) | severity critical พร้อมเวอร์ชันที่แก้และคำสั่งอัปเกรด |
| CVE ร้ายแรงใหม่ | [NVD](https://nvd.nist.gov) | CVSS 9.0 ขึ้นไป ทุก vendor (ไม่รวม plugin WordPress) |

## ทำงานยังไง

```
Cloudflare Worker (trigger/)  ทุก 5 นาที
  └─ สั่ง workflow_dispatch ─▶ GitHub Actions รัน watch.py ─▶ Discord
                                   └─ บันทึกรายการที่แจ้งแล้วใน state.json
```

cron ของ GitHub เองยังเปิดไว้เป็นสำรอง แต่ GitHub รันให้แค่ทุกไม่กี่ชั่วโมง

## Secrets

| อยู่ที่ | ชื่อ | ใช้ทำอะไร |
|---|---|---|
| GitHub repo secret | `DISCORD_WEBHOOK` | webhook ของ channel ที่จะรับข่าว (จำเป็น) |
| GitHub repo secret | `NVD_API_KEY` | ไม่บังคับ ช่วยกันโดน NVD จำกัดการเรียก [ขอฟรี](https://nvd.nist.gov/developers/request-an-api-key) |
| Cloudflare Worker secret | `GITHUB_TOKEN` | fine-grained token เฉพาะ repo นี้ สิทธิ์ Actions: Read and write |

## เปลี่ยน token

ทำเมื่อ Discord แจ้ง "ตัวสั่งรันทุก 5 นาทีหยุดทำงาน" หรือก่อน token หมดอายุ (ดูวันหมดอายุที่ [Personal access tokens](https://github.com/settings/personal-access-tokens))

1. [สร้าง token ใหม่](https://github.com/settings/personal-access-tokens/new): Repository access เลือก **Only select repositories** แล้วเลือก `security-alert` และ Permissions ให้ **Actions: Read and write**
2. ใส่ token ให้ Worker (ระบบจะให้วางแบบซ่อนตัวอักษร):

```bash
cd trigger && npx cf auth login && read -s "T?GitHub token: " && npx cf workers secrets update GITHUB_TOKEN --worker security-alert-trigger --text "$T"; unset T
```

## เปลี่ยน Discord webhook

```bash
gh secret set DISCORD_WEBHOOK -R NiraphatK/security-alert
```

## ดูตัวอย่างข้อความ

ส่งข่าวจริงของสัปดาห์นี้แบบละ 1 ข้อความเข้า Discord โดยไม่กระทบ state:

```bash
gh workflow run watch.yml -R NiraphatK/security-alert -f preview=true
```

## ข้อความเกี่ยวกับตัวเฝ้าเอง

| ข้อความ | ความหมาย |
|---|---|
| สรุป 24 ชั่วโมงที่ผ่านมา (09:00 ทุกวัน) | ยังทำงานอยู่ ถ้าวันไหนไม่มา แปลว่าตัวเฝ้าหยุดทำงาน ถ้าเป็นสีเหลือง แปลว่ารอบตรวจน้อยผิดปกติ |
| ดึงข่าวจาก ... ไม่ได้ / กลับมาใช้ได้แล้ว | แหล่งข่าวล่มติดกันประมาณ 30 นาที แหล่งอื่นยังทำงาน |
| ตัวสั่งรันทุก 5 นาทีหยุดทำงาน / กลับมาทำงานแล้ว | Worker ไม่ได้สั่งรันเกิน 20 นาที ส่วนใหญ่เพราะ token หมดอายุ ดูหัวข้อเปลี่ยน token |
| ตัวเฝ้าข่าวช่องโหว่ทำงานล้มเหลว / กลับมาทำงานปกติแล้ว | workflow พัง กดหัวข้อเพื่อดู log (แจ้งครั้งเดียวจนกว่าจะกลับมา) |

## ปรับความดัง

ค่าบนสุดของ [watch.py](watch.py): `GHSA_SEVERITIES` (เพิ่ม `"high"` ถ้าอยากได้มากขึ้น), `NVD_MIN_SCORE`, `MUTE_WORDS`, `MUTE_CNAS`

## พัฒนา

```bash
python3 -B test_watch.py
```

```bash
PREVIEW=true python3 watch.py
```

ถ้าไม่ได้ตั้ง `DISCORD_WEBHOOK` คำสั่งข้างบนจะพิมพ์ข้อความออกจอแทนการส่ง ส่วน Worker ใน `trigger/` deploy ด้วย `npx cf deploy` หลัง `npx cf auth login` และทุก push จะรันเทสต์ใน [test.yml](.github/workflows/test.yml)
