/**
 * Cloudflare Worker - 云端音乐 API
 * 项目名：yunduanyingyue
 * 接口地址：https://yunduanyingyue.tmichi1001.workers.dev/
 * 数据库：musicsguare_db
 */

// 简单的密码哈希函数（生产环境建议使用更安全的方案）
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'musicsquare_salt_2024');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// 生成JWT Token
async function generateToken(userId, username, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    userId,
    username,
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 // 7天过期
  };
  
  const base64Header = btoa(JSON.stringify(header)).replace(/=/g, '');
  const base64Payload = btoa(JSON.stringify(payload)).replace(/=/g, '');
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${base64Header}.${base64Payload}`)
  );
  
  const base64Signature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  
  return `${base64Header}.${base64Payload}.${base64Signature}`;
}

// 验证JWT Token
async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const [base64Header, base64Payload, base64Signature] = parts;
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureArray = Uint8Array.from(atob(base64Signature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureArray,
      encoder.encode(`${base64Header}.${base64Payload}`)
    );
    
    if (!valid) return null;
    
    const payload = JSON.parse(atob(base64Payload));
    
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    
    return payload;
  } catch (e) {
    return null;
  }
}

// CORS 响应头
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// JSON 响应
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders
    }
  });
}

// 错误响应
function errorResponse(message, status = 400) {
  return jsonResponse({ success: false, error: message }, status);
}

// 成功响应
function successResponse(data, message = 'success') {
  return jsonResponse({ success: true, message, data });
}

// 从请求中获取用户信息
async function getUserFromRequest(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  const token = authHeader.substring(7);
  const payload = await verifyToken(token, env.JWT_SECRET || 'musicsquare_jwt_secret_2024');
  
  return payload;
}

// 主处理函数
export default {
  async fetch(request, env, ctx) {
    // 处理 CORS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    
    try {
      // ==================== 用户认证相关 ====================
      
      // 注册
      if (path === '/api/register' && method === 'POST') {
        const body = await request.json();
        const { username, password } = body;
        
        if (!username || !password) {
          return errorResponse('用户名和密码不能为空');
        }
        
        if (username.length < 2 || username.length > 20) {
          return errorResponse('用户名长度应在2-20个字符之间');
        }
        
        if (password.length < 6) {
          return errorResponse('密码长度至少6个字符');
        }
        
        // 检查用户名是否已存在
        const existing = await env.DB.prepare(
          'SELECT id FROM users WHERE username = ?'
        ).bind(username).first();
        
        if (existing) {
          return errorResponse('用户名已存在');
        }
        
        const passwordHash = await hashPassword(password);
        
        const result = await env.DB.prepare(
          'INSERT INTO users (username, password_hash) VALUES (?, ?)'
        ).bind(username, passwordHash).run();
        
        const token = await generateToken(
          result.meta.last_row_id,
          username,
          env.JWT_SECRET || 'musicsquare_jwt_secret_2024'
        );
        
        return successResponse({ token, username }, '注册成功');
      }
      
      // 登录
      if (path === '/api/login' && method === 'POST') {
        const body = await request.json();
        const { username, password } = body;
        
        if (!username || !password) {
          return errorResponse('用户名和密码不能为空');
        }
        
        const user = await env.DB.prepare(
          'SELECT id, username, password_hash FROM users WHERE username = ?'
        ).bind(username).first();
        
        if (!user) {
          return errorResponse('用户名或密码错误');
        }
        
        const passwordHash = await hashPassword(password);
        
        if (user.password_hash !== passwordHash) {
          return errorResponse('用户名或密码错误');
        }
        
        const token = await generateToken(
          user.id,
          user.username,
          env.JWT_SECRET || 'musicsquare_jwt_secret_2024'
        );
        
        return successResponse({ token, username: user.username }, '登录成功');
      }
      
      // 验证Token
      if (path === '/api/verify' && method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('未登录或登录已过期', 401);
        }
        return successResponse({ userId: user.userId, username: user.username });
      }
      
      // ==================== 收藏相关 ====================
      
      // 获取收藏列表
      if (path === '/api/favorites' && method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const favorites = await env.DB.prepare(
          'SELECT id, song_uid, song_data, created_at FROM favorites WHERE user_id = ? ORDER BY created_at DESC'
        ).bind(user.userId).all();
        
        const songs = favorites.results.map(f => ({
          id: f.id,
          ...JSON.parse(f.song_data),
          created_at: f.created_at
        }));
        
        return successResponse(songs);
      }
      
      // 添加收藏
      if (path === '/api/favorites' && method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const body = await request.json();
        const { song } = body;
        
        if (!song || !song.uid) {
          return errorResponse('歌曲信息不完整');
        }
        
        try {
          await env.DB.prepare(
            'INSERT INTO favorites (user_id, song_uid, song_data) VALUES (?, ?, ?)'
          ).bind(user.userId, song.uid, JSON.stringify(song)).run();
          
          return successResponse(null, '收藏成功');
        } catch (e) {
          if (e.message.includes('UNIQUE constraint')) {
            return errorResponse('已经收藏过了');
          }
          throw e;
        }
      }
      
      // 删除收藏
      if (path.startsWith('/api/favorites/') && method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const songUid = decodeURIComponent(path.split('/api/favorites/')[1]);
        
        await env.DB.prepare(
          'DELETE FROM favorites WHERE user_id = ? AND song_uid = ?'
        ).bind(user.userId, songUid).run();
        
        return successResponse(null, '取消收藏成功');
      }
      
      // ==================== 歌单相关 ====================
      
      // 获取歌单列表
      if (path === '/api/playlists' && method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const playlists = await env.DB.prepare(
          'SELECT id, name, created_at FROM playlists WHERE user_id = ? ORDER BY created_at DESC'
        ).bind(user.userId).all();
        
        // 获取每个歌单的歌曲数量
        const playlistsWithCount = await Promise.all(
          playlists.results.map(async (pl) => {
            const count = await env.DB.prepare(
              'SELECT COUNT(*) as count FROM playlist_songs WHERE playlist_id = ?'
            ).bind(pl.id).first();
            return { ...pl, songCount: count.count };
          })
        );
        
        return successResponse(playlistsWithCount);
      }
      
      // 创建歌单
      if (path === '/api/playlists' && method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const body = await request.json();
        const { name } = body;
        
        if (!name || name.trim().length === 0) {
          return errorResponse('歌单名称不能为空');
        }
        
        const result = await env.DB.prepare(
          'INSERT INTO playlists (user_id, name) VALUES (?, ?)'
        ).bind(user.userId, name.trim()).run();
        
        return successResponse({ id: result.meta.last_row_id, name: name.trim() }, '创建成功');
      }
      
      // 删除歌单
      if (path.match(/^\/api\/playlists\/\d+$/) && method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const playlistId = parseInt(path.split('/').pop());
        
        // 验证歌单属于当前用户
        const playlist = await env.DB.prepare(
          'SELECT id FROM playlists WHERE id = ? AND user_id = ?'
        ).bind(playlistId, user.userId).first();
        
        if (!playlist) {
          return errorResponse('歌单不存在');
        }
        
        // 删除歌单中的歌曲
        await env.DB.prepare(
          'DELETE FROM playlist_songs WHERE playlist_id = ?'
        ).bind(playlistId).run();
        
        // 删除歌单
        await env.DB.prepare(
          'DELETE FROM playlists WHERE id = ?'
        ).bind(playlistId).run();
        
        return successResponse(null, '删除成功');
      }
      
      // 歌单重命名
      if (path.match(/^\/api\/playlists\/\d+$/) && method === 'PATCH') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        const playlistId = parseInt(path.split('/').pop());
        const body = await request.json();
        const { name } = body;
        if (!name || name.trim().length === 0) {
          return errorResponse('歌单名称不能为空');
        }
        // 验证歌单属于当前用户
        const playlist = await env.DB.prepare(
          'SELECT id FROM playlists WHERE id = ? AND user_id = ?'
        ).bind(playlistId, user.userId).first();
        if (!playlist) {
          return errorResponse('歌单不存在');
        }
        await env.DB.prepare(
          'UPDATE playlists SET name = ? WHERE id = ?'
        ).bind(name.trim(), playlistId).run();
        return successResponse(null, '重命名成功');
      }

      // 获取歌单详情（包含歌曲）
      if (path.match(/^\/api\/playlists\/\d+$/) && method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const playlistId = parseInt(path.split('/').pop());
        
        const playlist = await env.DB.prepare(
          'SELECT id, name, created_at FROM playlists WHERE id = ? AND user_id = ?'
        ).bind(playlistId, user.userId).first();
        
        if (!playlist) {
          return errorResponse('歌单不存在');
        }
        
        const songs = await env.DB.prepare(
          'SELECT id, song_uid, song_data, created_at FROM playlist_songs WHERE playlist_id = ? ORDER BY created_at DESC'
        ).bind(playlistId).all();
        
        const songList = songs.results.map(s => ({
          id: s.id,
          ...JSON.parse(s.song_data),
          created_at: s.created_at
        }));
        
        return successResponse({ ...playlist, songs: songList });
      }
      
      // 添加歌曲到歌单
      if (path.match(/^\/api\/playlists\/\d+\/songs$/) && method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const playlistId = parseInt(path.split('/')[3]);
        
        // 验证歌单属于当前用户
        const playlist = await env.DB.prepare(
          'SELECT id FROM playlists WHERE id = ? AND user_id = ?'
        ).bind(playlistId, user.userId).first();
        
        if (!playlist) {
          return errorResponse('歌单不存在');
        }
        
        const body = await request.json();
        const { song } = body;
        
        if (!song || !song.uid) {
          return errorResponse('歌曲信息不完整');
        }
        
        try {
          await env.DB.prepare(
            'INSERT INTO playlist_songs (playlist_id, song_uid, song_data) VALUES (?, ?, ?)'
          ).bind(playlistId, song.uid, JSON.stringify(song)).run();
          
          return successResponse(null, '添加成功');
        } catch (e) {
          if (e.message.includes('UNIQUE constraint')) {
            return errorResponse('歌曲已在歌单中');
          }
          throw e;
        }
      }
      
      // 从歌单删除歌曲
      if (path.match(/^\/api\/playlists\/\d+\/songs\//) && method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const parts = path.split('/');
        const playlistId = parseInt(parts[3]);
        const songUid = decodeURIComponent(parts[5]);
        
        // 验证歌单属于当前用户
        const playlist = await env.DB.prepare(
          'SELECT id FROM playlists WHERE id = ? AND user_id = ?'
        ).bind(playlistId, user.userId).first();
        
        if (!playlist) {
          return errorResponse('歌单不存在');
        }
        
        await env.DB.prepare(
          'DELETE FROM playlist_songs WHERE playlist_id = ? AND song_uid = ?'
        ).bind(playlistId, songUid).run();
        
        return successResponse(null, '删除成功');
      }
      
      // ==================== 播放历史相关 ====================
      
      // 获取播放历史
      if (path === '/api/history' && method === 'GET') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        
        const history = await env.DB.prepare(
          `SELECT DISTINCT song_uid, song_data, MAX(played_at) as played_at 
           FROM play_history 
           WHERE user_id = ? 
           GROUP BY song_uid 
           ORDER BY played_at DESC 
           LIMIT ?`
        ).bind(user.userId, limit).all();
        
        const songs = history.results.map(h => ({
          ...JSON.parse(h.song_data),
          played_at: h.played_at
        }));
        
        return successResponse(songs);
      }
      
      // 添加播放历史
      if (path === '/api/history' && method === 'POST') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        const body = await request.json();
        const { song } = body;
        
        if (!song || !song.uid) {
          return errorResponse('歌曲信息不完整');
        }
        
        await env.DB.prepare(
          'INSERT INTO play_history (user_id, song_uid, song_data) VALUES (?, ?, ?)'
        ).bind(user.userId, song.uid, JSON.stringify(song)).run();
        
        // 清理旧的历史记录，只保留最近200条
        await env.DB.prepare(
          `DELETE FROM play_history WHERE user_id = ? AND id NOT IN (
            SELECT id FROM play_history WHERE user_id = ? ORDER BY played_at DESC LIMIT 200
          )`
        ).bind(user.userId, user.userId).run();
        
        return successResponse(null, '记录成功');
      }
      
      // 清空播放历史
      if (path === '/api/history' && method === 'DELETE') {
        const user = await getUserFromRequest(request, env);
        if (!user) {
          return errorResponse('请先登录', 401);
        }
        
        await env.DB.prepare(
          'DELETE FROM play_history WHERE user_id = ?'
        ).bind(user.userId).run();
        
        return successResponse(null, '清空成功');
      }
      
      // ==================== 热门歌曲（模拟数据）====================
      
      if (path === '/api/hot' && method === 'GET') {
        // 返回一些热门搜索关键词
        const hotKeywords = [
          '周杰伦', '林俊杰', '邓紫棋', '薛之谦', '陈奕迅',
          '王菲', '李荣浩', '毛不易', '华晨宇', '张学友',
          '刘德华', '周深', '张杰', '许嵩', '汪苏泷'
        ];
        return successResponse(hotKeywords);
      }
      
      // 默认响应
      return jsonResponse({
        success: true,
        message: '云端音乐 API 服务运行中',
        version: '1.0.0',
        endpoints: [
          'POST /api/register - 注册',
          'POST /api/login - 登录',
          'GET /api/verify - 验证Token',
          'GET /api/favorites - 获取收藏',
          'POST /api/favorites - 添加收藏',
          'DELETE /api/favorites/:songUid - 删除收藏',
          'GET /api/playlists - 获取歌单列表',
          'POST /api/playlists - 创建歌单',
          'DELETE /api/playlists/:id - 删除歌单',
          'GET /api/playlists/:id - 获取歌单详情',
          'POST /api/playlists/:id/songs - 添加歌曲到歌单',
          'DELETE /api/playlists/:id/songs/:songUid - 从歌单删除歌曲',
          'GET /api/history - 获取播放历史',
          'POST /api/history - 添加播放历史',
          'DELETE /api/history - 清空播放历史',
          'GET /api/hot - 获取热门关键词'
        ]
      });
      
    } catch (error) {
      console.error('Error:', error);
      return errorResponse('服务器内部错误: ' + error.message, 500);
    }
  }
};
