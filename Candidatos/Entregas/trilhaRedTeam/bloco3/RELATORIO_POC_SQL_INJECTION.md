# Relatório Técnico de Prova de Conceito (PoC)

## Bypass de autenticação por SQL Injection — OWASP Juice Shop

**Programa:** Onboarding SACI 2026.2 — Trilha Red Team  
**Entrega:** Bloco 3  
**Aplicação-alvo:** OWASP Juice Shop (ambiente de treinamento)  
**Vulnerabilidade:** SQL Injection (SQLi) no formulário de autenticação  
**Referências:** CWE-89 (SQL Injection), OWASP A03:2021 — Injection  
**Data do relatório:** 20/11/2026  
**Estado da comprovação:** evidências de execução pendentes de anexação

> \*\*Escopo e transparência:\*\* Este documento descreve uma PoC reproduzível em um laboratório intencionalmente vulnerável. O payload foi indicado como procedimento de teste; não foram fornecidos prints ou registros que comprovem sua execução bem-sucedida nesta instância. Portanto, o acesso ao perfil do administrador \*\*não está declarado como verificado\*\* neste relatório.

## 1\. Objetivo

Demonstrar como a concatenação insegura de valores fornecidos pelo usuário em uma instrução SQL pode permitir o bypass da verificação de senha e a autenticação como administrador na aplicação OWASP Juice Shop. Identificar a causa raiz e propor remediação por **Prepared Statements / Parameterized Queries**.

## 2\. Descrição da falha

### 2.1. Conceito

SQL Injection ocorre quando dados controlados por um usuário são incorporados à estrutura de uma consulta SQL sem a devida separação entre **código da consulta** e **valores de entrada**. O mecanismo do banco de dados pode passar a interpretar caracteres enviados no formulário como parte da linguagem SQL, alterando a lógica originalmente pretendida pelo desenvolvedor.

No contexto do formulário de login, os campos de e-mail e senha são enviados ao backend para que a aplicação localize uma conta e valide suas credenciais. Quando a instrução SQL é montada por concatenação de strings, um valor malicioso no campo de e-mail pode manipular a condição `WHERE`.

### 2.2. Exemplo didático de consulta vulnerável

```sql
SELECT \* FROM Users
WHERE email = '<email\_digitado>'
  AND password = '<senha\_digitada>';
```

Esse exemplo é **esquemático**: não representa uma transcrição comprovada do código-fonte ou da consulta exata executada pelo Juice Shop. Em sistemas reais, senhas não devem ser armazenadas ou comparadas em texto puro; a verificação correta deve empregar hash de senha apropriado.

### 2.3. Causa raiz e impacto

A causa raiz é a montagem de instruções SQL com entrada não confiável. Uma exploração pode permitir **bypass de autenticação** e **acesso não autorizado a contas**, com impacto elevado sobre a confidencialidade e a integridade das informações. Neste exercício, o impacto previsto é o acesso à conta de administrador sem conhecimento da senha.

## 3\. Passo a passo da exploração

### 3.1. Ambiente e pré-condições

* Instância do OWASP Juice Shop disponível em ambiente autorizado de laboratório.
* Navegador com acesso ao formulário **Account → Login**.
* Nenhuma credencial real de administrador necessária para o teste.

### 3.2. Payload proposto

**Campo e-mail:**

```text
admin@juice-sh.op'--
```

**Campo senha:**

```text
123456
```

O payload acima é o **valor exato a inserir no laboratório**. Não há informação nesta conversa que confirme que esse foi o valor efetivamente submetido durante uma tentativa realizada.

### 3.3. Procedimento de reprodução

1. Iniciar ou acessar a instância do OWASP Juice Shop.
2. Abrir o menu **Account → Login**.
3. Inserir `admin@juice-sh.op'--` no campo de e-mail.
4. Inserir `123456` no campo de senha (valor arbitrário).
5. Acionar **Log in**.
6. Registrar o resultado: mensagem do desafio **Login Admin**, identidade da conta autenticada e/ou tela do perfil do administrador.
7. Caso o login falhe, registrar também a falha; versões, configurações e validações de entrada podem alterar o comportamento.

### 3.4. Mecanismo técnico

A aspa simples (`'`) encerra antecipadamente o literal de texto usado para o e-mail, enquanto `--` introduz um comentário SQL. Se esses caracteres forem concatenados diretamente à consulta e interpretados pelo banco, o trecho posterior referente à senha pode ser ignorado.

Exemplo **ilustrativo** da consulta resultante:

```sql
SELECT \* FROM Users
WHERE email = 'admin@juice-sh.op'--'
  AND password = '123456';
```

Na sintaxe SQL em que `--` comenta o restante da linha, a condição de senha não participa efetivamente da consulta, permitindo selecionar a conta associada ao e-mail informado. O sucesso da autenticação também depende da implementação específica do backend e de como a aplicação processa o resultado.

### 3.5. Evidências da PoC

**Evidência 01 — Formulário de login com payload inserido**  
Arquivo previsto: `evidencias/01-payload-login.png`  
**Status:** pendente. Inserir captura real do campo de e-mail contendo o payload antes do envio.

!\[Evidência 01 — capturar formulário com payload](loginJuiceShop.png)

**Evidência 02 — Login concluído com conta de administrador**  
Arquivo previsto: `evidencias/02-login-admin.png`  
**Status:** pendente. Inserir captura real mostrando a conta `admin@juice-sh.op` autenticada, o perfil de administrador ou a notificação de conclusão do desafio.

!\[Evidência 02 — capturar acesso autenticado ao administrador](autenticado.png)

**Resultado esperado:** bypass de senha e autenticação como administrador.  
**Resultado observado:** não documentado; a captura de tela fornecida contém apenas as instruções da missão, não o resultado da exploração.  
**Conclusão experimental:** pendente da coleta das evidências acima.

## 4\. Remediação recomendada

### 4.1. Prepared Statements / Parameterized Queries

A medida principal consiste em preparar a **estrutura fixa** da consulta SQL e transmitir entradas do usuário **separadamente como parâmetros**. Desse modo, caracteres como `'`, `--` e sequências SQL fornecidas no e-mail permanecem dados literais: não encerram strings e não alteram a expressão `WHERE`.

#### Exemplo inseguro (Node.js, padrão ilustrativo)

```javascript
// NÃO UTILIZAR: concatena entrada do usuário em SQL.
const email = req.body.email;
const sql = `SELECT id, email, password\_hash FROM users WHERE email = '${email}'`;
const result = await db.query(sql);
```

#### Exemplo corrigido (Node.js + PostgreSQL, biblioteca `pg`)

```javascript
import bcrypt from 'bcrypt';

async function login(req, res) {
  const { email, password } = req.body;

  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Entrada inválida' });
  }

  // A consulta e seus valores são enviados separadamente ao driver.
  const { rows } = await db.query(
    'SELECT id, email, password\_hash, role FROM users WHERE email = $1 LIMIT 1',
    \[email]
  );

  const account = rows\[0];
  if (!account || !(await bcrypt.compare(password, account.password\_hash))) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // Exemplo: criar sessão segura somente após verificar a senha.
  req.session.userId = account.id;
  return res.status(200).json({ message: 'Autenticação realizada' });
}
```

**Observação técnica:** o código acima é um exemplo de implementação segura **em PostgreSQL**, não uma afirmação sobre a tecnologia ou o código exato do Juice Shop. A aplicação real pode utilizar outra biblioteca, dialeto SQL ou ORM; a correção deve seguir o mecanismo de parametrização oficialmente suportado por esse stack.

### 4.2. Por que a correção impede o ataque

Com a consulta parametrizada:

```sql
SELECT id, email, password\_hash, role
FROM users
WHERE email = $1
LIMIT 1;
```

e com o valor de `$1` igual a `admin@juice-sh.op'--`, o banco procura **literalmente** um e-mail contendo esses caracteres. O trecho `--` não vira comentário SQL, e nenhuma parte da verificação de credenciais é suprimida. A senha fornecida somente é aceita se corresponder ao hash armazenado para o usuário encontrado.

### 4.3. Controles complementares

* Aplicar parametrização a **todas** as consultas que recebem dados externos, não apenas ao login.
* Armazenar senhas usando função apropriada de hash com sal e custo configurável, como **Argon2id** ou **bcrypt**; nunca armazenar senhas em texto puro.
* Garantir que a autenticação valide a senha **antes** de criar sessão ou emitir tokens.
* Validar formatos e limites de tamanho na entrada, sem tratar validação como substituto de consultas parametrizadas.
* Aplicar princípio do menor privilégio à conta de banco utilizada pela aplicação.
* Adotar mensagens de erro genéricas ao usuário, logs internos de segurança e limitação de tentativas de login.
* Manter testes automatizados de regressão que enviem payloads como `admin@juice-sh.op'--` e confirmem a rejeição da autenticação.

### 4.4. Critério de aceite da correção

A remediação estará validada quando o payload de SQLi for tratado apenas como texto de entrada, **não permitir a criação de uma sessão autenticada** e um login legítimo com credenciais válidas continuar funcionando normalmente.

## 5\. Conclusão

O cenário proposto demonstra uma falha crítica de separação entre dados e comandos SQL no processo de autenticação. A manipulação do e-mail com uma aspa de fechamento e um comentário SQL pode eliminar a condição de senha quando a consulta é construída por concatenação insegura. O uso de **Prepared Statements / Parameterized Queries**, aliado à verificação correta de hashes de senha, impede que entradas do usuário modifiquem a estrutura SQL.



