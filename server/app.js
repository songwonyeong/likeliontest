// server/app.js
const express = require('express') // Express 프레임워크 불러오기 (웹 서버 구축에 사용)
const cors = require('cors') // CORS(Cross-Origin Resource Sharing) 미들웨어 불러오기 (도메인 간 요청 허용)
const bcrypt = require('bcrypt')// 비밀번호 암호화를 위한 bcrypt 라이브러리 불러오기
const connection = require('./db') // MySQL 등 데이터베이스 연결 모듈 불러오기 (직접 만든 db.js 파일)
const app = express() // express 앱 생성 (서버 객체 만들기)
const port = 3000 // 사용할 포트 번호 지정 (3000번 포트)
const path = require('path') // 경로(path) 관련 내장 모듈 불러오기 (파일 경로 지정에 사용)
const cookieParser = require('cookie-parser') // 쿠키 파싱 미들웨어 불러오기 (쿠키를 쉽게 다루기 위해 사용)

app.use(cookieParser())
app.use(cors())
app.use(express.json())

app.use(express.static(path.join(__dirname, '..')))

// 회원가입
app.post('/signup', async (req, res) => {
  const { ID, PW } = req.body
  if (!ID || !PW) return res.status(400).json({ message: 'ID/PW 필수' })

  try {
    const hashedPW = await bcrypt.hash(PW, 10) // 비밀번호 해쉬 사용 
    const sql = 'INSERT INTO users (ID, PW) VALUES (?, ?)' // SQL 쿼리문으로 아이디, 비밀번호 데이터 삽입
    connection.query(sql, [ID, hashedPW], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') { // 이미 존재하는 아이디일 경우우
          return res.status(409).json({ message: '이미 존재하는 ID입니다.' })
        }
        return res.status(500).json({ message: 'DB 오류' })
      }
      res.status(201).json({ message: '회원가입 완료' })
    })
  } catch (err) {
    res.status(500).json({ message: '해시 오류' })
  }
})

app.post('/login', (req, res) => {
  const { ID, PW } = req.body
  if (!ID || !PW) return res.status(400).json({ message: 'ID/PW 필수' })

  const sql = 'SELECT * FROM users WHERE ID = ?' // users 테이블 조회 쿼리문
  connection.query(sql, [ID], async (err, results) => {
    if (err) return res.status(500).json({ message: 'DB 오류' })
    if (results.length === 0) return res.status(401).json({ message: '존재하지 않는 ID입니다.' }) 

    const user = results[0]
    const isMatch = await bcrypt.compare(PW, user.PW)

    if (!isMatch) {
      return res.status(401).json({ message: '비밀번호가 틀렸습니다.' })
    }

    // ✅ 쿠키 설정 추가
    res.cookie('user', ID, { // 'user'라는 이름으로 ID값을 쿠키에 저장
      httpOnly: false, 
      maxAge: 1000 * 60 * 60 * 24 // maxAge: 쿠키 유효기간을 24시간(밀리초 기준)으로 설정 (1일)
    });

    res.status(200).json({ message: '로그인 성공!' })
  })
})


// 계정 삭제하기
app.delete('/delete-account', (req, res) => {
  const { ID } = req.body;
  if (!ID) return res.status(400).json({ message: 'ID 필수' });

  const sql = 'DELETE FROM users WHERE ID = ?';
  connection.query(sql, [ID], (err, result) => {
    if (err) return res.status(500).json({ message: 'DB 오류' });

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: '해당 ID를 찾을 수 없습니다.' });
    }

    res.status(200).json({ message: '회원 탈퇴 완료' });
  });
});


app.listen(port, () => {
  console.log(`🚀 서버 실행 중: http://localhost:${port}`)
})

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'login.html'));
});
