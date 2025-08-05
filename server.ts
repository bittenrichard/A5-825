// Local: server.ts

import dotenv from 'dotenv';

// Garante que variáveis de ambiente sejam carregadas apenas em desenvolvimento.
// Em produção, elas devem ser injetadas pelo serviço de hospedagem.
if (process.env.NODE_ENV !== 'production') {
  dotenv.config();
}

import express, { Request, Response } from 'express';
import cors from 'cors';
import { google } from 'googleapis';
import { baserowServer } from './src/shared/services/baserowServerClient.js';
import fetch from 'node-fetch';
import bcrypt from 'bcryptjs';
import multer from 'multer';

const app = express();
const port = process.env.PORT || 3001;

const upload = multer(); // Configuração do Multer para upload de arquivos em memória

// --- Configuração de CORS para Produção ---
// Permite requisições apenas do seu frontend oficial para máxima segurança.
const corsOptions = {
  origin: process.env.FRONTEND_URL,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Validação crítica das credenciais do Google na inicialização
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REDIRECT_URI) {
  console.error("ERRO CRÍTICO: As credenciais do Google (CLIENT_ID, CLIENT_SECRET, REDIRECT_URI) não foram encontradas no ambiente.");
  process.exit(1); // Interrompe a inicialização se as chaves estiverem faltando
}

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// --- CONSTANTES DE IDs DAS TABELAS BASEROW ---
const USERS_TABLE_ID = '711';
const VAGAS_TABLE_ID = '709';
const CANDIDATOS_TABLE_ID = '710';
const WHATSAPP_CANDIDATOS_TABLE_ID = '712';
const AGENDAMENTOS_TABLE_ID = '713';
const SALT_ROUNDS = 10;

// --- INTERFACES PARA TIPAGEM DOS DADOS DO BASEROW ---
interface BaserowJobPosting {
  id: number;
  titulo: string;
  usuario?: { id: number; value: string }[];
}

interface BaserowCandidate {
  id: number;
  vaga?: { id: number; value: string }[] | string | null;
  usuario?: { id: number; value: string }[] | null;
  nome: string;
  telefone: string | null;
  curriculo?: { url: string; name: string }[] | null;
  score?: number | null;
  resumo_ia?: string | null;
  status?: { id: number; value: 'Triagem' | 'Entrevista' | 'Aprovado' | 'Reprovado' } | null;
  data_triagem?: string;
  sexo?: string | null;
  escolaridade?: string | null;
  idade?: number | null;
}


// --- ENDPOINTS DE AUTENTICAÇÃO ---

app.post('/api/auth/signup', async (req: Request, res: Response) => {
  const { nome, empresa, telefone, email, password } = req.body;
  if (!email || !password || !nome) {
    return res.status(400).json({ error: 'Nome, e-mail e senha são obrigatórios.' });
  }

  try {
    const emailLowerCase = email.toLowerCase();
    const { results: existingUsers } = await baserowServer.get(USERS_TABLE_ID, `?filter__Email__equal=${emailLowerCase}`);

    if (existingUsers && existingUsers.length > 0) {
      return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = await baserowServer.post(USERS_TABLE_ID, {
      nome,
      empresa,
      telefone,
      Email: emailLowerCase,
      senha_hash: hashedPassword,
    });

    const userProfile = {
      id: newUser.id,
      nome: newUser.nome,
      email: newUser.Email,
      empresa: newUser.empresa,
      telefone: newUser.telefone,
      avatar_url: newUser.avatar_url || null,
      google_refresh_token: newUser.google_refresh_token || null,
    };

    res.status(201).json({ success: true, user: userProfile });
  } catch (error: any) {
    console.error('Erro no endpoint /api/auth/signup:', error);
    res.status(500).json({ error: 'Ocorreu um erro interno ao tentar criar a conta.' });
  }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
  }

  try {
    const emailLowerCase = email.toLowerCase();
    const { results: users } = await baserowServer.get(USERS_TABLE_ID, `?filter__Email__equal=${emailLowerCase}`);
    const user = users && users[0];

    if (!user || !user.senha_hash) {
      return res.status(401).json({ error: 'E-mail ou senha inválidos.' });
    }

    const passwordMatches = await bcrypt.compare(password, user.senha_hash);

    if (passwordMatches) {
      const userProfile = {
        id: user.id,
        nome: user.nome,
        email: user.Email,
        empresa: user.empresa,
        telefone: user.telefone,
        avatar_url: user.avatar_url || null,
        google_refresh_token: user.google_refresh_token || null,
      };
      res.json({ success: true, user: userProfile });
    } else {
      res.status(401).json({ error: 'E-mail ou senha inválidos.' });
    }
  } catch (error: any) {
    console.error('Erro no endpoint /api/auth/login:', error);
    res.status(500).json({ error: 'Ocorreu um erro interno ao tentar fazer login.' });
  }
});

// --- ENDPOINTS PARA GERENCIAR O PERFIL DO USUÁRIO ---
app.patch('/api/users/:userId/profile', async (req: Request, res: Response) => {
  const { userId } = req.params;
  const { nome, empresa, avatar_url } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'ID do usuário é obrigatório.' });
  }

  try {
    const updatedData: Record<string, any> = {};
    if (nome !== undefined) updatedData.nome = nome;
    if (empresa !== undefined) updatedData.empresa = empresa;
    if (avatar_url !== undefined) updatedData.avatar_url = avatar_url;

    if (Object.keys(updatedData).length === 0) {
      return res.status(400).json({ error: 'Nenhum dado para atualizar.' });
    }

    const updatedUser = await baserowServer.patch(USERS_TABLE_ID, parseInt(userId), updatedData);

    const userProfile = {
      id: updatedUser.id,
      nome: updatedUser.nome,
      email: updatedUser.Email,
      empresa: updatedUser.empresa,
      telefone: updatedUser.telefone,
      avatar_url: updatedUser.avatar_url || null,
      google_refresh_token: updatedUser.google_refresh_token || null,
    };

    res.status(200).json({ success: true, user: userProfile });
  } catch (error: any) {
    console.error('Erro no endpoint /api/users/:userId/profile:', error);
    res.status(500).json({ error: 'Não foi possível atualizar o perfil.' });
  }
});

app.patch('/api/users/:userId/password', async (req: Request, res: Response) => {
  const { userId } = req.params;
  const { password } = req.body;

  if (!userId || !password) {
    return res.status(400).json({ error: 'ID do usuário e nova senha são obrigatórios.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await baserowServer.patch(USERS_TABLE_ID, parseInt(userId), { senha_hash: hashedPassword });
    res.json({ success: true, message: 'Senha atualizada com sucesso!' });
  } catch (error: any) {
    console.error('Erro no endpoint /api/users/:userId/password:', error);
    res.status(500).json({ error: 'Não foi possível atualizar a senha.' });
  }
});

app.get('/api/users/:userId', async (req: Request, res: Response) => {
  const { userId } = req.params;
  if (!userId) {
    return res.status(400).json({ error: 'ID do usuário é obrigatório.' });
  }
  try {
    const user = await baserowServer.getRow(USERS_TABLE_ID, parseInt(userId));
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }
    const userProfile = {
      id: user.id,
      nome: user.nome,
      email: user.Email,
      empresa: user.empresa,
      telefone: user.telefone,
      avatar_url: user.avatar_url || null,
      google_refresh_token: user.google_refresh_token || null,
    };
    res.json(userProfile);
  } catch (error: any) {
    console.error('Erro no endpoint /api/users/:userId:', error);
    res.status(500).json({ error: 'Não foi possível buscar o perfil do usuário.' });
  }
});

// --- ENDPOINT: UPLOAD DE AVATAR ---
app.post('/api/upload-avatar', upload.single('avatar'), async (req: Request, res: Response) => {
  const userId = req.body.userId;
  if (!userId || !req.file) {
    return res.status(400).json({ error: 'Arquivo e ID do usuário são obrigatórios.' });
  }

  try {
    const uploadedFile = await baserowServer.uploadFileFromBuffer(req.file.buffer, req.file.originalname, req.file.mimetype);
    const updatedUser = await baserowServer.patch(USERS_TABLE_ID, parseInt(userId), { avatar_url: uploadedFile.url });

    const userProfile = {
      id: updatedUser.id,
      nome: updatedUser.nome,
      email: updatedUser.Email,
      empresa: updatedUser.empresa,
      telefone: updatedUser.telefone,
      avatar_url: updatedUser.avatar_url || null,
      google_refresh_token: updatedUser.google_refresh_token || null,
    };
    res.json({ success: true, avatar_url: uploadedFile.url, user: userProfile });

  } catch (error: any) {
    console.error('Erro no endpoint /api/upload-avatar:', error);
    res.status(500).json({ error: error.message || 'Não foi possível fazer upload do avatar.' });
  }
});


// --- ENDPOINTS PARA OPERAÇÕES DE VAGAS (JOBS) ---

app.post('/api/jobs', async (req: Request, res: Response) => {
  const { titulo, descricao, endereco, requisitos_obrigatorios, requisitos_desejaveis, usuario } = req.body;
  if (!titulo || !descricao || !usuario || !Array.isArray(usuario) || usuario.length === 0) {
    return res.status(400).json({ error: 'Título, descrição e um usuário associado são obrigatórios.' });
  }

  try {
    const createdJob = await baserowServer.post(VAGAS_TABLE_ID, {
      titulo,
      descricao,
      Endereco: endereco,
      requisitos_obrigatorios,
      requisitos_desejaveis,
      usuario,
    });
    res.status(201).json(createdJob);
  } catch (error: any) {
    console.error('Erro no endpoint /api/jobs (POST):', error);
    res.status(500).json({ error: 'Não foi possível criar a vaga.' });
  }
});

app.patch('/api/jobs/:jobId', async (req: Request, res: Response) => {
  const { jobId } = req.params;
  const updatedData = req.body;
  if (!jobId || Object.keys(updatedData).length === 0) {
    return res.status(400).json({ error: 'ID da vaga e dados para atualização são obrigatórios.' });
  }

  try {
    const updatedJob = await baserowServer.patch(VAGAS_TABLE_ID, parseInt(jobId), updatedData);
    res.json(updatedJob);
  } catch (error: any) {
    console.error('Erro no endpoint /api/jobs/:jobId (PATCH):', error);
    res.status(500).json({ error: 'Não foi possível atualizar a vaga.' });
  }
});

app.delete('/api/jobs/:jobId', async (req: Request, res: Response) => {
  const { jobId } = req.params;
  if (!jobId) {
    return res.status(400).json({ error: 'ID da vaga é obrigatório.' });
  }

  try {
    await baserowServer.delete(VAGAS_TABLE_ID, parseInt(jobId));
    res.status(204).send();
  } catch (error: any) {
    console.error('Erro no endpoint /api/jobs/:jobId (DELETE):', error);
    res.status(500).json({ error: 'Não foi possível excluir a vaga.' });
  }
});

// --- ENDPOINTS PARA OPERAÇÕES DE CANDIDATOS ---

app.patch('/api/candidates/:candidateId/status', async (req: Request, res: Response) => {
  const { candidateId } = req.params;
  const { status } = req.body;

  if (!candidateId || !status) {
    return res.status(400).json({ error: 'ID do candidato e status são obrigatórios.' });
  }
  const validStatuses = ['Triagem', 'Entrevista', 'Aprovado', 'Reprovado'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Status inválido.' });
  }

  try {
    const updatedCandidate = await baserowServer.patch(CANDIDATOS_TABLE_ID, parseInt(candidateId), { status });
    res.json(updatedCandidate);
  } catch (error: any) {
    console.error('Erro no endpoint /api/candidates/:candidateId/status:', error);
    res.status(500).json({ error: 'Não foi possível atualizar o status do candidato.' });
  }
});

// --- ENDPOINT CENTRALIZADO PARA BUSCAR TODOS OS DADOS (VAGAS, CANDIDATOS, ETC.) ---
app.get('/api/data/all/:userId', async (req: Request, res: Response) => {
  const { userId } = req.params;
  if (!userId) {
    return res.status(400).json({ error: 'ID do usuário é obrigatório.' });
  }

  try {
    const [jobsResult, regularCandidatesResult, whatsappCandidatesResult] = await Promise.all([
      baserowServer.get(VAGAS_TABLE_ID, `?filter__usuario__link_row_has=${userId}`),
      baserowServer.get(CANDIDATOS_TABLE_ID, `?filter__usuario__link_row_has=${userId}`),
      baserowServer.get(WHATSAPP_CANDIDATOS_TABLE_ID, `?filter__usuario__link_row_has=${userId}`)
    ]);

    const userJobs: BaserowJobPosting[] = (jobsResult.results || []) as BaserowJobPosting[];
    const allCandidatesRaw: BaserowCandidate[] = [
      ...(regularCandidatesResult.results || []),
      ...(whatsappCandidatesResult.results || [])
    ] as BaserowCandidate[];

    res.json({ jobs: userJobs, candidates: allCandidatesRaw });

  } catch (error: any) {
    console.error('Erro no endpoint /api/data/all/:userId:', error);
    res.status(500).json({ error: 'Falha ao carregar dados.' });
  }
});


// --- ENDPOINT PARA UPLOAD DE MÚLTIPLOS CURRÍCULOS E DISPARO DE WEBHOOK ---
app.post('/api/upload-curriculums', upload.array('curriculumFiles'), async (req: Request, res: Response) => {
  const { jobId, userId } = req.body;
  const files = req.files as Express.Multer.File[];

  if (!jobId || !userId || !files || files.length === 0) {
    return res.status(400).json({ error: 'Vaga, usuário e arquivos de currículo são obrigatórios.' });
  }

  try {
    const newCandidateEntries = [];
    for (const file of files) {
      if (file.size > 5 * 1024 * 1024) { // Limite de 5MB por arquivo
          return res.status(400).json({ success: false, message: `O arquivo '${file.originalname}' excede o limite de 5MB.` });
      }

      const uploadedFile = await baserowServer.uploadFileFromBuffer(file.buffer, file.originalname, file.mimetype);

      const createdCandidate = await baserowServer.post(CANDIDATOS_TABLE_ID, {
        nome: file.originalname.split('.').slice(0, -1).join('.') || 'Novo Candidato',
        curriculo: [{ name: uploadedFile.name, url: uploadedFile.url }],
        usuario: [parseInt(userId)],
        vaga: [parseInt(jobId)],
        status: 'Triagem',
      });
      newCandidateEntries.push(createdCandidate);
    }
    
    // Disparo do Webhook em Lote (se configurado)
    const N8N_TRIAGEM_WEBHOOK_URL = process.env.N8N_TRIAGEM_WEBHOOK_URL;
    if (N8N_TRIAGEM_WEBHOOK_URL && newCandidateEntries.length > 0) {
      const [jobInfo, userInfo] = await Promise.all([
        baserowServer.getRow(VAGAS_TABLE_ID, parseInt(jobId)),
        baserowServer.getRow(USERS_TABLE_ID, parseInt(userId))
      ]);

      if (jobInfo && userInfo) {
        const webhookPayload = {
          tipo: 'triagem_curriculo_lote',
          recrutador: { id: userInfo.id, nome: userInfo.nome, email: userInfo.Email, empresa: userInfo.empresa },
          vaga: { id: jobInfo.id, titulo: jobInfo.titulo, descricao: jobInfo.descricao, endereco: jobInfo.Endereco, requisitos_obrigatorios: jobInfo.requisitos_obrigatorios, requisitos_desejaveis: jobInfo.requisitos_desejaveis },
          candidatos: newCandidateEntries.map(c => ({ id: c.id, nome: c.nome, curriculo_url: c.curriculo?.[0]?.url }))
        };

        fetch(N8N_TRIAGEM_WEBHOOK_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(webhookPayload)
        }).catch(err => console.error("Erro assíncrono ao disparar webhook para n8n:", err));
      }
    }

    res.json({ success: true, message: `${files.length} currículo(s) enviado(s) para análise!`, newCandidates: newCandidateEntries });

  } catch (error: any) {
    console.error('Erro no endpoint /api/upload-curriculums:', error);
    res.status(500).json({ success: false, message: 'Falha no servidor ao processar os currículos.' });
  }
});

// --- ENDPOINT PARA BUSCAR AGENDAMENTOS ---
app.get('/api/schedules/:userId', async (req: Request, res: Response) => {
  const { userId } = req.params;
  if (!userId) {
    return res.status(400).json({ error: 'ID do usuário é obrigatório.' });
  }

  try {
    const { results } = await baserowServer.get(AGENDAMENTOS_TABLE_ID, `?filter__Candidato__usuario__link_row_has=${userId}`);
    res.json({ success: true, results: results || [] });
  } catch (error: any) {
    console.error('Erro no endpoint /api/schedules/:userId:', error);
    res.status(500).json({ success: false, message: 'Falha ao buscar agendamentos.' });
  }
});

// --- ENDPOINTS DE INTEGRAÇÃO GOOGLE CALENDAR ---

app.get('/api/google/auth/connect', (req: Request, res: Response) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: 'userId é obrigatório' });

  const scopes = ['https://www.googleapis.com/auth/calendar.events'];
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline', scope: scopes, prompt: 'consent', state: userId.toString(),
  });
  res.json({ url });
});

app.get('/api/google/auth/callback', async (req: Request, res: Response) => {
  const { code, state: userId } = req.query;
  const closePopupScript = `<script>window.close();</script>`;

  if (!code || typeof userId !== 'string') {
    return res.send(closePopupScript);
  }

  try {
    const { tokens } = await oauth2Client.getToken(code as string);
    if (tokens.refresh_token) {
        await baserowServer.patch(USERS_TABLE_ID, parseInt(userId), { google_refresh_token: tokens.refresh_token });
    }
  } catch (error) {
    console.error('Erro no callback do Google OAuth:', error);
  } finally {
    res.send(closePopupScript);
  }
});

app.post('/api/google/auth/disconnect', async (req: Request, res: Response) => {
    const { userId } = req.body;
    await baserowServer.patch(USERS_TABLE_ID, parseInt(userId), { google_refresh_token: null });
    res.json({ success: true, message: 'Conta Google desconectada.' });
});

app.post('/api/google/calendar/create-event', async (req: Request, res: Response) => {
    const { userId, eventData, candidate, job } = req.body;
    if (!userId || !eventData || !candidate || !job) {
        return res.status(400).json({ success: false, message: 'Dados insuficientes para criar o evento.' });
    }

    try {
        const userResponse = await baserowServer.getRow(USERS_TABLE_ID, parseInt(userId));
        const refreshToken = userResponse.google_refresh_token;
        if (!refreshToken) {
            return res.status(401).json({ success: false, message: 'Usuário não conectado ao Google Calendar.' });
        }

        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const calendar = google.calendar({ version: 'v3', auth: oauth2Client });
        
        const event = {
            summary: eventData.title,
            description: `Entrevista com: ${candidate.nome}.\nTelefone: ${candidate.telefone || 'N/A'}\n\nDetalhes: ${eventData.details || 'N/A'}`,
            start: { dateTime: eventData.start, timeZone: 'America/Sao_Paulo' },
            end: { dateTime: eventData.end, timeZone: 'America/Sao_Paulo' },
            reminders: { useDefault: true },
        };

        const { data: googleEvent } = await calendar.events.insert({ calendarId: 'primary', requestBody: event });

        await baserowServer.post(AGENDAMENTOS_TABLE_ID, {
          'Título': eventData.title,
          'Início': eventData.start,
          'Fim': eventData.end,
          'Detalhes': eventData.details,
          'Candidato': [candidate.id],
          'Vaga': [job.id],
          'google_event_link': googleEvent.htmlLink
        });
        
        // Disparo do Webhook de agendamento (se configurado)
        const N8N_SCHEDULE_WEBHOOK_URL = process.env.N8N_SCHEDULE_WEBHOOK_URL;
        if (N8N_SCHEDULE_WEBHOOK_URL) {
            const webhookPayload = {
                recruiter: { id: userResponse.id, nome: userResponse.nome, email: userResponse.Email, empresa: userResponse.empresa }, 
                candidate, 
                job,
                interview: { title: eventData.title, startTime: eventData.start, endTime: eventData.end, details: eventData.details, googleEventLink: googleEvent.htmlLink }
            };
            fetch(N8N_SCHEDULE_WEBHOOK_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(webhookPayload)
            }).catch(err => console.error("Erro assíncrono ao disparar webhook de agendamento:", err));
        }

        res.json({ success: true, message: 'Evento criado com sucesso!', data: googleEvent });
    } catch (error) {
        console.error('Erro ao criar evento no Google Calendar:', error);
        res.status(500).json({ success: false, message: 'Falha ao criar o evento no Google Calendar.' });
    }
});

// Inicia o servidor
app.listen(port, () => {
  console.log(`Backend de produção rodando na porta ${port}`);
});