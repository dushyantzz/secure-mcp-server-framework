# Secure MCP Server Framework

## What is this project?
This is a secure, easy-to-use server that lets AI assistants like Claude or GPT safely access your tools, scripts, and APIs. It acts as a professional "security guard" between AI and your valuable resources, so you always stay in control.

---

## Why did people need this?

**Before:**
- Many AI/automation tools could run your code, but anyone could connect, and there were no real safety checks built in.
- Most open MCP servers are like vending machines on the street: they let anyone press buttons, break things, or spend your money quickly. There's no login, no limit, no logs, and no safety net.

**Problems this caused:**
- People (or bots) could spam your tools, rack up big bills, or break important stuff.
- There was no way to see who did what, when, or why—so if anything went wrong, you couldn’t track it.
- Sensitive actions (deleting files, changing configs) could be done by anyone who found your server.

---

## How does Secure MCP Server solve the problem?

**This project adds multiple strong security layers:**

| Security Layer        | What it does                                            | How it works                                                              |
|----------------------|--------------------------------------------------------|---------------------------------------------------------------------------|
| **Authentication**   | Only lets in people with correct username & password   | Uses secure password hashing (bcrypt) and issues tokens after login        |
| **Authorization**    | Separates admin from regular users                     | Checks user role before letting them call sensitive tools                  |
| **Rate Limiting**    | Stops spam and abuse                                   | Automatically blocks tools after 60 requests per hour per user             |
| **Input Validation** | Blocks dangerous commands from running                 | Code checks all inputs, blocks risky phrases (like 'delete files')         |
| **Audit Logging**    | Records who did what, when                             | Every tool use, error, and blocked action is written to a secure log       |
| **Sandboxing**       | Runs tools in isolated mode                            | Prevents tools from accessing files, system, or other risky resources      |
| **Token Checking**   | Requires every action to have a valid access token     | Blocks any user or bot who tries to act without a real token               |

**In short:**
- ONLY the right person can use the right tool.
- Every attempt (good or bad) is logged.
- Rate limits stop spamming, cost overruns, and accidental infinite loops.
- Even if someone tries something risky, tools run in a secure sandbox that can't touch your system files.

---

## How does it protect you compared to a basic MCP server?

|                    | Basic MCP Server            | Secure MCP Server             |
|--------------------|----------------------------|------------------------------|
| Login Required     | ❌ No (open to all)         | ✅ Yes (username & password)  |
| Admin Permissions  | ❌ No                       | ✅ Yes (only admin sees sensitive info) |
| Spam Protection    | ❌ No                       | ✅ Yes (rate limits)          |
| Blocks Dangerous   | ❌ No                       | ✅ Yes (input check & sandbox)|
| Activity Logs      | ❌ No                       | ✅ Yes (audit logging)        |
| Knows Who Did What| ❌ No                        | ✅ Yes                        |
| Safe For Business  | ❌ No                       | ✅ Yes                        |

---

## What technologies make this possible?
- **Python 3.9+**: Easy to read and fast to develop in.
- **FastMCP & MCP SDK**: Handles messages between AI and your server, so any AI app that uses MCP can connect.
- **passlib + bcrypt**: Keeps passwords safe so nobody can steal them.
- **python-jose (JWT)**: Makes the 'ID cards' (tokens) that prove who each user is.
- **SQLAlchemy + SQLite**: Saves user, log, and tool data simply; easy to upgrade to PostgreSQL for big teams.
- **structlog & prometheus**: Simple, searchable logs and graphs to see how your system is running.
- **psutil**: Lets you monitor your own server’s CPU/memory usage.
- **pydantic, python-dotenv**: Clean, safe ways to use environment variables and settings.

---

## Typical life of a request (How the layers protect you)
1. **User logs in** with username & password → gets a secure token.
2. Every time they do anything, the **token** is checked (like showing their ID card).
3. Before any tool runs, the server double-checks:
   - Are you allowed to do this? (admin vs. regular user)
   - Have you already used this tool too many times? (rate limiting)
   - Is your request safe? (input check)
   - Are you inside of your allowed memory? (context)
4. If all is good, the tool runs inside a **sandbox** (safe zone) so nothing dangerous can escape.
5. Every attempt (success or blocked) is written to the **audit log** for full traceability.
6. If anyone acts suspicious, they’re blocked and the admin can see everything in the logs.

---

## In summary
- **Secure MCP Server** gives you all the power of an MCP server
- **PLUS** enterprise-level safety and logs
- It adds a professional security guard, not just an open gateway
- Perfect for anyone who wants to run real workflows or tools with AI, safely

