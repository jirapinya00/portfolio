// user.js - โหลดข้อมูล user จาก token แล้วแสดงผลบนหน้าเว็บ
(function(){
  const token = localStorage.getItem('access_token');
  if (!token) {
    // ถ้าไม่มี token ให้ redirect ไป login
    window.location.href = "/login";
    return;
  }

  fetch('/api/auth/profile', {
    headers: {
      'Authorization': 'Bearer ' + token
    }
  })
  .then(res => {
    if (!res.ok) {
      // token หมดอายุ หรือไม่ถูกต้อง
      localStorage.removeItem('access_token');
      localStorage.removeItem('user_data');
      window.location.href = "/login";
      throw new Error('Unauthorized');
    }
    return res.json();
  })
  .then(data => {
    if (data.user && data.user.username) {
      // สมมติให้มี element id="userName" ไว้แสดงชื่อผู้ใช้
      const el = document.getElementById("userName");
      if(el) el.innerText = data.user.username;
    }
  })
  .catch(err => {
    console.error('Error loading user profile:', err);
  });
})();
