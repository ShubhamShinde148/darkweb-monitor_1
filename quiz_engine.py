import os
from groq import Groq
# === AI PROVIDER HELPERS ===
def generate_with_groq(prompt, model="mixtral-8x7b-32768", temperature=0.7, max_tokens=1024):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise Exception("GROQ_API_KEY not set")
    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content.strip()

def generate_with_gemini(prompt, model="gemini-2.0-flash", temperature=0.7, max_tokens=1024):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise Exception("GEMINI_API_KEY not set")
    from google import genai
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config={"temperature": temperature, "max_output_tokens": max_tokens},
    )
    return response.text.strip()

def generate_ai_content(prompt, static_fallback, model_groq="mixtral-8x7b-32768", model_gemini="gemini-2.0-flash"):
    try:
        return generate_with_groq(prompt, model=model_groq)
    except Exception as groq_err:
        logger.warning(f"GROQ failed: {groq_err}")
        try:
            return generate_with_gemini(prompt, model=model_gemini)
        except Exception as gemini_err:
            logger.warning(f"Gemini failed: {gemini_err}")
            return static_fallback
"""
Cybersecurity Quiz Engine
=========================
20-question quiz with scoring and certificate generation.
Supports both static questions and AI-generated questions via OpenAI.
"""


import random
import copy
import os
import json
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import hashlib

# Configure logging for the module
logger = logging.getLogger("quiz_engine")
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[QUIZ_ENGINE] %(asctime)s %(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


@dataclass
class Question:
    """Represents a quiz question."""
    id: int
    question: str
    options: List[str]
    correct_answer: int  # Index of correct option (0-3)
    category: str
    difficulty: str  # easy, medium, hard
    explanation: str


@dataclass
class QuizResult:
    """Stores quiz completion results."""
    quiz_id: str
    participant_name: str
    email: str
    score: int
    total: int
    percentage: float
    passed: bool
    completion_time: str
    answers: Dict[int, int]
    category_scores: Dict[str, Dict]


# ==================== AI QUIZ GENERATOR ====================


class AIQuizGenerator:
    """Generate cybersecurity quiz questions using Google Gemini API, with robust fallback and logging."""

    CATEGORIES = [
        "Password Security",
        "Phishing Attacks",
        "Network Security",
        "Malware & Threats",
        "Web Security",
        "Data Breaches",
        "OSINT",
        "Cryptography",
        "Authentication",
        "Social Engineering"
    ]


    DIFFICULTY_PROMPTS = {
        "beginner": "suitable for people new to cybersecurity. Focus on basic concepts, common threats, and simple best practices.",
        "intermediate": "for people with some security knowledge. Include technical concepts, attack methods, and security protocols.",
        "advanced": "for cybersecurity professionals. Include complex technical details, advanced attack vectors, CVEs, and expert-level concepts."
    }

    # Static fallback question bank (minimal example, expand as needed)
    STATIC_QUESTIONS = [
        {
            "id": 1,
            "question": "What is phishing?",
            "options": ["A type of malware", "A social engineering attack", "A firewall", "A password manager"],
            "correct_answer": 1,
            "category": "Phishing Attacks",
            "difficulty": "beginner",
            "explanation": "Phishing is a social engineering attack to trick users into revealing sensitive information."
        },
        {
            "id": 2,
            "question": "Which is the strongest password?",
            "options": ["password123", "QwErTy!@#2022", "letmein", "123456"],
            "correct_answer": 1,
            "category": "Password Security",
            "difficulty": "beginner",
            "explanation": "Strong passwords use a mix of upper/lowercase, numbers, and symbols."
        },
        {
            "id": 3,
            "question": "What does a firewall do?",
            "options": ["Encrypts data", "Blocks unauthorized access", "Stores passwords", "Detects phishing emails"],
            "correct_answer": 1,
            "category": "Network Security",
            "difficulty": "beginner",
            "explanation": "A firewall blocks unauthorized access to or from a network."
        },
        {
            "id": 4,
            "question": "What is OSINT?",
            "options": ["Open Source Intelligence", "Operating System Interface", "Online Security Integration", "Overt Security Investigation"],
            "correct_answer": 0,
            "category": "OSINT",
            "difficulty": "intermediate",
            "explanation": "OSINT stands for Open Source Intelligence."
        },
        {
            "id": 5,
            "question": "Which protocol secures web traffic?",
            "options": ["HTTP", "FTP", "SSH", "HTTPS"],
            "correct_answer": 3,
            "category": "Web Security",
            "difficulty": "intermediate",
            "explanation": "HTTPS encrypts web traffic for secure communication."
        }
    ]

    @staticmethod
    def filter_unique_questions(questions: list) -> list:
        """Remove duplicate questions by text using a set."""
        seen = set()
        unique = []
        for q in questions:
            text = q["question"].strip().lower()
            if text not in seen:
                seen.add(text)
                unique.append(q)
        return unique

    @staticmethod
    def get_category_pools(questions: list) -> dict:
        """Organize questions into pools by category."""
        pools = {}
        for q in questions:
            cat = q.get("category", "General Security")
            pools.setdefault(cat, []).append(q)
        return pools

    @staticmethod
    def select_random_questions(pools: dict, category: str, count: int) -> list:
        """Randomly select unique questions from a category pool."""
        pool = pools.get(category, [])
        if len(pool) < count:
            count = len(pool)
        
        {
            "id": 5,
            "question": "Which protocol secures web traffic?",
            "options": ["HTTP", "FTP", "SSH", "HTTPS"],
            "correct_answer": 3,
            "category": "Web Security",
            "difficulty": "intermediate",
            "explanation": "HTTPS encrypts web traffic for secure communication."
        }
    

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self._client = None

    @property
    def client(self):
        """Lazy load Gemini client."""
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
                return None
        return self._client

    def generate_questions(self, count: int = 10, difficulty: str = "intermediate", category_distribution: Optional[Dict[str, int]] = None) -> Optional[List[Dict]]:
        """
        Generate quiz questions using GROQ API, fallback to Gemini, then static questions.
        """
        count = max(5, min(20, count))
        if difficulty == "advanced" and count > 10:
            count = 10
        difficulty = difficulty.lower() if difficulty.lower() in self.DIFFICULTY_PROMPTS else "intermediate"
        selected_categories = list(self.CATEGORIES)
        categories_str = ", ".join(selected_categories)
        prompt = f"""Generate {count} cybersecurity quiz questions ({self.DIFFICULTY_PROMPTS[difficulty]})\n\nTopics: {categories_str}\n\nRules:\n- 4 options each, one correct\n- Keep questions and options SHORT and concise\n\nReturn ONLY valid JSON (no markdown):\n[{{\"question\":\"Q?\",\"options\":[\"A\",\"B\",\"C\",\"D\"],\"correct_answer\":\"A\",\"category\":\"Cat\",\"difficulty\":\"{difficulty}\",\"explanation\":\"Why\"}}]"""
        static_fallback = self._get_static_questions(count, difficulty)
        content = generate_ai_content(prompt, static_fallback)
        # If fallback is already a list, use it
        if isinstance(content, list):
            questions = content
        else:
            # Otherwise, try to parse the AI response as JSON
            try:
                if isinstance(content, str):
                    if content.startswith("```"):
                        content = content.split("```")[1]
                        if content.startswith("json"):
                            content = content[4:]
                        content = content.strip()
                    if content.endswith("```"):
                        content = content[:-3].strip()
                    questions = json.loads(content)
                else:
                    questions = content
            except Exception:
                logger.warning("Failed to parse AI response, using static fallback.")
                questions = static_fallback

        # Validate and normalize each question
        validated = []
        for i, q in enumerate(questions):
            if not all(k in q for k in ["question", "options", "correct_answer"]):
                continue
            if len(q["options"]) != 4:
                continue
            correct_idx = -1
            for idx, opt in enumerate(q["options"]):
                if opt.strip().lower() == q["correct_answer"].strip().lower():
                    correct_idx = idx
                    break
            if correct_idx == -1:
                for idx, opt in enumerate(q["options"]):
                    if q["correct_answer"].strip().lower() in opt.strip().lower() or opt.strip().lower() in q["correct_answer"].strip().lower():
                        correct_idx = idx
                        break
            if correct_idx == -1:
                correct_idx = 0
            validated.append({
                "id": i + 1,
                "question": q["question"],
                "options": q["options"],
                "correct_answer": correct_idx,
                "category": q.get("category", "General Security"),
                "difficulty": q.get("difficulty", difficulty),
                "explanation": q.get("explanation", "")
            })

        # Remove duplicates
        unique_validated = self.filter_unique_questions(validated)

        # If a category distribution is provided, select accordingly
        if category_distribution:
            pools = self.get_category_pools(unique_validated)
            selected = []
            for cat, num in category_distribution.items():
                selected += self.select_random_questions(pools, cat, num)
            # Remove any accidental duplicates (across categories)
            selected = self.filter_unique_questions(selected)
            if len(selected) < sum(category_distribution.values()):
                logger.warning(f"Not enough unique questions for requested distribution. Returning {len(selected)}.")
            return selected
        else:
            # Otherwise, just return up to 'count' unique questions
            if len(unique_validated) < count:
                logger.warning(f"Only {len(unique_validated)} unique questions generated. Returning all.")
                return unique_validated
            return random.sample(unique_validated, count)

    def _get_static_questions(self, count: int, difficulty: str) -> List[Dict]:
        """Return static fallback questions, filtered by difficulty if possible."""
        filtered = [q for q in self.STATIC_QUESTIONS if q["difficulty"] == difficulty]
        if not filtered:
            filtered = self.STATIC_QUESTIONS
        # Repeat or trim to match count
        result = (filtered * ((count // len(filtered)) + 1))[:count]
        logger.info(f"Returning {len(result)} static fallback questions.")
        return result
    
    def create_quiz_session(self, questions: List[Dict], shuffle: bool = True) -> Dict:
        """
        Create a quiz session from AI-generated questions.
        
        Args:
            questions: List of question dictionaries from generate_questions()
            shuffle: Whether to shuffle questions and options
            
        Returns:
            Quiz session dictionary
        """
        quiz_id = hashlib.md5(f"{datetime.now().isoformat()}{random.random()}AI".encode()).hexdigest()[:12]
        
        # Convert to Question objects
        question_objects = []
        for q in questions:
            question_objects.append(Question(
                id=q["id"],
                question=q["question"],
                options=q["options"].copy(),
                correct_answer=q["correct_answer"],
                category=q["category"],
                difficulty=q["difficulty"],
                explanation=q.get("explanation", "")
            ))
        
        if shuffle:
            random.shuffle(question_objects)
            for q in question_objects:
                options_with_idx = list(enumerate(q.options))
                random.shuffle(options_with_idx)
                new_correct = next(i for i, (orig_i, _) in enumerate(options_with_idx) if orig_i == q.correct_answer)
                q.options = [opt for _, opt in options_with_idx]
                q.correct_answer = new_correct
        
        # Re-number questions after shuffle
        for i, q in enumerate(question_objects):
            q.id = i + 1
        
        return {
            "quiz_id": quiz_id,
            "total_questions": len(question_objects),
            "pass_threshold": 70,
            "ai_generated": True,
            "questions": question_objects,  # Return actual Question objects for storage
            "questions_json": [
                {
                    "id": q.id,
                    "question": q.question,
                    "options": q.options,
                    "category": q.category,
                    "difficulty": q.difficulty
                }
                for q in question_objects
            ]
        }


# Global AI quiz generator instance
ai_quiz_generator = AIQuizGenerator()


class CybersecurityQuiz:
    """20-Question Cybersecurity Knowledge Quiz."""
    
    PASS_THRESHOLD = 70  # 70% to pass
    
    def __init__(self):
        self.questions = self._load_questions()
        self.active_quizzes: Dict[str, List[Question]] = {}
    
    def _load_questions(self) -> List[Question]:
        """Load all quiz questions."""
        questions = [
            # Password Security (4 questions)
            Question(
                id=1,
                question="What is the minimum recommended length for a strong password?",
                options=["6 characters", "8 characters", "12 characters", "16 characters"],
                correct_answer=2,
                category="Password Security",
                difficulty="easy",
                explanation="Security experts recommend at least 12 characters for strong passwords. Longer passwords are exponentially harder to crack."
            ),
            Question(
                id=2,
                question="Which password practice is MOST dangerous?",
                options=["Using a password manager", "Reusing passwords across sites", "Using passphrases", "Enabling 2FA"],
                correct_answer=1,
                category="Password Security",
                difficulty="easy",
                explanation="Reusing passwords means if one site is breached, all your accounts using that password are compromised."
            ),
            Question(
                id=3,
                question="What does 'salting' a password mean?",
                options=["Adding special characters", "Adding random data before hashing", "Encrypting twice", "Storing in plain text"],
                correct_answer=1,
                category="Password Security",
                difficulty="medium",
                explanation="Salting adds random data to passwords before hashing, making rainbow table attacks ineffective."
            ),
            Question(
                id=4,
                question="Which hashing algorithm is considered UNSAFE for passwords?",
                options=["bcrypt", "Argon2", "MD5", "scrypt"],
                correct_answer=2,
                category="Password Security",
                difficulty="medium",
                explanation="MD5 is cryptographically broken and too fast for password hashing, making brute-force attacks feasible."
            ),
            
            # Two-Factor Authentication (3 questions)
            Question(
                id=5,
                question="Which 2FA method is considered the MOST secure?",
                options=["SMS codes", "Email codes", "Hardware security keys", "Security questions"],
                correct_answer=2,
                category="Authentication",
                difficulty="medium",
                explanation="Hardware security keys (FIDO2/WebAuthn) are phishing-resistant and cannot be intercepted like SMS."
            ),
            Question(
                id=6,
                question="What is a TOTP code?",
                options=["A permanent password", "A time-based one-time password", "A recovery code", "A biometric scan"],
                correct_answer=1,
                category="Authentication",
                difficulty="easy",
                explanation="TOTP (Time-based One-Time Password) generates codes that change every 30 seconds, used by apps like Google Authenticator."
            ),
            Question(
                id=7,
                question="Why is SMS-based 2FA vulnerable?",
                options=["It's too slow", "SIM swapping attacks", "It requires internet", "It's too expensive"],
                correct_answer=1,
                category="Authentication",
                difficulty="hard",
                explanation="Attackers can convince carriers to transfer your number to their SIM (SIM swapping), intercepting your SMS codes."
            ),
            
            # Phishing & Social Engineering (4 questions)
            Question(
                id=8,
                question="What is 'spear phishing'?",
                options=["Mass spam emails", "Targeted attacks on specific individuals", "Fishing website scams", "Malware distribution"],
                correct_answer=1,
                category="Phishing",
                difficulty="medium",
                explanation="Spear phishing targets specific individuals with personalized content, making it more convincing than mass phishing."
            ),
            Question(
                id=9,
                question="Which URL is most likely a phishing attempt?",
                options=["https://google.com", "https://google.secure-login.com", "https://mail.google.com", "https://accounts.google.com"],
                correct_answer=1,
                category="Phishing",
                difficulty="easy",
                explanation="'google.secure-login.com' is a subdomain of 'secure-login.com', not Google. Always check the main domain."
            ),
            Question(
                id=10,
                question="What is 'vishing'?",
                options=["Video phishing", "Voice/phone phishing", "Virtual phishing", "Virus phishing"],
                correct_answer=1,
                category="Phishing",
                difficulty="medium",
                explanation="Vishing (voice phishing) uses phone calls to trick victims into revealing sensitive information."
            ),
            Question(
                id=11,
                question="What should you do if you receive a suspicious email from your 'bank'?",
                options=["Click the link to verify", "Reply asking for confirmation", "Contact your bank directly using official numbers", "Forward it to friends"],
                correct_answer=2,
                category="Phishing",
                difficulty="easy",
                explanation="Never use links or numbers from suspicious emails. Contact organizations through their official website or known phone numbers."
            ),
            
            # Network Security (3 questions)
            Question(
                id=12,
                question="What does a VPN primarily protect?",
                options=["Your computer from viruses", "Your internet traffic from eavesdropping", "Your passwords from hackers", "Your files from deletion"],
                correct_answer=1,
                category="Network Security",
                difficulty="easy",
                explanation="VPNs encrypt your internet traffic, protecting it from eavesdropping, especially on public WiFi networks."
            ),
            Question(
                id=13,
                question="What is a 'man-in-the-middle' attack?",
                options=["Physical theft", "Intercepting communications between two parties", "Denial of service", "SQL injection"],
                correct_answer=1,
                category="Network Security",
                difficulty="medium",
                explanation="MITM attacks intercept and potentially alter communications between two parties who believe they're communicating directly."
            ),
            Question(
                id=14,
                question="Why is public WiFi risky?",
                options=["It's too slow", "Attackers can intercept unencrypted traffic", "It costs money", "It drains battery"],
                correct_answer=1,
                category="Network Security",
                difficulty="easy",
                explanation="Public WiFi often lacks encryption, allowing attackers on the same network to intercept your data."
            ),
            
            # Data Breaches (3 questions)
            Question(
                id=15,
                question="What should you do FIRST after learning your data was in a breach?",
                options=["Delete your account", "Change your password immediately", "Contact a lawyer", "Ignore it"],
                correct_answer=1,
                category="Data Breaches",
                difficulty="easy",
                explanation="Immediately changing your password prevents attackers from using leaked credentials to access your account."
            ),
            Question(
                id=16,
                question="What is 'credential stuffing'?",
                options=["Creating fake credentials", "Using leaked passwords to try logging into other sites", "Encrypting credentials", "Storing passwords securely"],
                correct_answer=1,
                category="Data Breaches",
                difficulty="hard",
                explanation="Credential stuffing uses username/password pairs from one breach to attempt logins on other services, exploiting password reuse."
            ),
            Question(
                id=17,
                question="What is 'k-anonymity' in breach checking?",
                options=["Keeping data secret", "Sending only partial password hashes for privacy", "Anonymous browsing", "Encrypting all data"],
                correct_answer=1,
                category="Data Breaches",
                difficulty="hard",
                explanation="K-anonymity sends only partial password hashes, so the service can check for breaches without knowing your actual password."
            ),
            
            # Malware & Threats (3 questions)
            Question(
                id=18,
                question="What is ransomware?",
                options=["Software that displays ads", "Malware that encrypts files and demands payment", "A type of antivirus", "Network monitoring tool"],
                correct_answer=1,
                category="Malware",
                difficulty="easy",
                explanation="Ransomware encrypts your files and demands payment (usually in cryptocurrency) for the decryption key."
            ),
            Question(
                id=19,
                question="What is a 'zero-day' vulnerability?",
                options=["A bug with no impact", "An unknown vulnerability being actively exploited", "A patched security flaw", "A virus that activates at midnight"],
                correct_answer=1,
                category="Malware",
                difficulty="hard",
                explanation="Zero-day vulnerabilities are unknown to vendors and have no patch available, making them extremely dangerous."
            ),
            Question(
                id=20,
                question="What is the safest action when downloading software?",
                options=["Download from any site", "Use torrent sites", "Download only from official sources", "Disable antivirus first"],
                correct_answer=2,
                category="Malware",
                difficulty="easy",
                explanation="Official sources verify software integrity. Third-party sites may bundle malware with legitimate software."
            ),
        ]
        return questions
    
    def start_quiz(self, shuffle: bool = True) -> Dict:
        """Start a new quiz session."""
        quiz_id = hashlib.md5(f"{datetime.now().isoformat()}{random.random()}".encode()).hexdigest()[:12]
        
        questions = copy.deepcopy(self.questions)
        if shuffle:
            random.shuffle(questions)
            # Also shuffle options for each question
            for q in questions:
                options_with_correct = list(enumerate(q.options))
                random.shuffle(options_with_correct)
                new_correct = next(i for i, (orig_i, _) in enumerate(options_with_correct) if orig_i == q.correct_answer)
                q.options = [opt for _, opt in options_with_correct]
                q.correct_answer = new_correct
        
        self.active_quizzes[quiz_id] = questions
        
        return {
            "quiz_id": quiz_id,
            "total_questions": len(questions),
            "pass_threshold": self.PASS_THRESHOLD,
            "questions": [
                {
                    "id": q.id,
                    "question": q.question,
                    "options": q.options,
                    "category": q.category,
                    "difficulty": q.difficulty
                }
                for q in questions
            ]
        }
    
    def submit_quiz(self, quiz_id: str, participant_name: str, email: str, answers: Dict[int, int]) -> Optional[QuizResult]:
        """Submit quiz answers and calculate results."""
        if quiz_id not in self.active_quizzes:
            return None
        
        questions = self.active_quizzes[quiz_id]
        correct = 0
        category_scores: Dict[str, Dict] = {}
        
        for q in questions:
            cat = q.category
            if cat not in category_scores:
                category_scores[cat] = {"correct": 0, "total": 0}
            category_scores[cat]["total"] += 1
            
            if answers.get(q.id) == q.correct_answer:
                correct += 1
                category_scores[cat]["correct"] += 1
        
        total = len(questions)
        percentage = (correct / total) * 100 if total > 0 else 0
        passed = percentage >= self.PASS_THRESHOLD
        
        result = QuizResult(
            quiz_id=quiz_id,
            participant_name=participant_name,
            email=email,
            score=correct,
            total=total,
            percentage=round(percentage, 1),
            passed=passed,
            completion_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            answers=answers,
            category_scores=category_scores
        )
        
        # Clean up active quiz
        del self.active_quizzes[quiz_id]
        
        return result
    
    def get_detailed_results(self, quiz_id: str, answers: Dict[int, int]) -> List[Dict]:
        """Get detailed results with explanations."""
        if quiz_id not in self.active_quizzes:
            return []
        
        questions = self.active_quizzes[quiz_id]
        results = []
        
        for q in questions:
            user_answer = answers.get(q.id, -1)
            results.append({
                "question_id": q.id,
                "question": q.question,
                "options": q.options,
                "user_answer": user_answer,
                "correct_answer": q.correct_answer,
                "is_correct": user_answer == q.correct_answer,
                "explanation": q.explanation,
                "category": q.category
            })
        
        return results
    
    def get_categories(self) -> List[str]:
        """Get all question categories."""
        return list(set(q.category for q in self.questions))


# Certificate generation using ReportLab
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import io
import math


class CertificateGenerator:
    """Generate professional PDF certificates for quiz completion."""
    
    def __init__(self):
        self.width, self.height = landscape(letter)
    
    def _draw_shield_icon(self, c, x, y, size, fill_color, stroke_color):
        """Draw a shield icon at the specified position."""
        p = c.beginPath()
        s = size
        p.moveTo(x, y + s * 0.5)
        p.curveTo(x, y + s * 0.85, x + s * 0.2, y + s, x + s * 0.5, y + s)
        p.curveTo(x + s * 0.8, y + s, x + s, y + s * 0.85, x + s, y + s * 0.5)
        p.lineTo(x + s, y + s * 0.15)
        p.curveTo(x + s * 0.75, y + s * 0.1, x + s * 0.55, y, x + s * 0.5, y - s * 0.15)
        p.curveTo(x + s * 0.45, y, x + s * 0.25, y + s * 0.1, x, y + s * 0.15)
        p.close()
        c.setFillColor(fill_color)
        c.setStrokeColor(stroke_color)
        c.setLineWidth(1.5)
        c.drawPath(p, fill=1, stroke=1)
    
    def _draw_decorative_corners(self, c, x1, y1, x2, y2, color, length=40):
        """Draw decorative corner brackets."""
        c.setStrokeColor(color)
        c.setLineWidth(2.5)
        # Top-left
        c.line(x1, y1, x1 + length, y1)
        c.line(x1, y1, x1, y1 - length)
        # Top-right
        c.line(x2, y1, x2 - length, y1)
        c.line(x2, y1, x2, y1 - length)
        # Bottom-left
        c.line(x1, y2, x1 + length, y2)
        c.line(x1, y2, x1, y2 + length)
        # Bottom-right
        c.line(x2, y2, x2 - length, y2)
        c.line(x2, y2, x2, y2 + length)
    
    def _draw_hexagon(self, c, cx, cy, radius, fill_color, stroke_color):
        """Draw a hexagonal shape."""
        p = c.beginPath()
        for i in range(6):
            angle = math.radians(60 * i - 30)
            px = cx + radius * math.cos(angle)
            py = cy + radius * math.sin(angle)
            if i == 0:
                p.moveTo(px, py)
            else:
                p.lineTo(px, py)
        p.close()
        c.setFillColor(fill_color)
        c.setStrokeColor(stroke_color)
        c.setLineWidth(2)
        c.drawPath(p, fill=1, stroke=1)
    
    def _draw_circuit_lines(self, c, color):
        """Draw subtle circuit-board pattern as background decoration."""
        c.saveState()
        c.setStrokeColor(color)
        c.setLineWidth(0.5)
        
        # Horizontal lines with nodes
        lines = [
            (60, self.height - 80, 180, self.height - 80),
            (self.width - 180, self.height - 80, self.width - 60, self.height - 80),
            (60, 80, 180, 80),
            (self.width - 180, 80, self.width - 60, 80),
            (60, self.height / 2 - 10, 100, self.height / 2 - 10),
            (self.width - 100, self.height / 2 - 10, self.width - 60, self.height / 2 - 10),
        ]
        for x1, y1, x2, y2 in lines:
            c.line(x1, y1, x2, y2)
            c.circle(x1, y1, 2, fill=1)
            c.circle(x2, y2, 2, fill=1)
        
        # Vertical accent lines
        c.line(60, 80, 60, 140)
        c.line(self.width - 60, 80, self.width - 60, 140)
        c.line(60, self.height - 140, 60, self.height - 80)
        c.line(self.width - 60, self.height - 140, self.width - 60, self.height - 80)
        
        c.restoreState()
    
    def generate(self, result: QuizResult, certificate_id: str = None) -> bytes:
        """Generate a compact professional PDF certificate (landscape letter)."""
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=landscape(letter))
        c.setTitle("Cybersecurity Awareness Certificate")
        c.setAuthor("Dark Web Monitor")

        # Colors
        primary = HexColor("#00ff88")
        primary_dim = HexColor("#00cc6a")
        secondary = HexColor("#00d4ff")
        dark = HexColor("#0a0a1a")
        dark2 = HexColor("#0f0f2a")
        dark3 = HexColor("#141432")
        gold = HexColor("#ffd700")
        gold_dim = HexColor("#b8960f")
        white = HexColor("#ffffff")
        light_gray = HexColor("#c0c0d0")
        mid_gray = HexColor("#808090")
        circuit_color = HexColor("#1a1a3e")

        cx = self.width / 2

        # ── Background ──
        c.setFillColor(dark)
        c.rect(0, 0, self.width, self.height, fill=1)

        # Subtle gradient bands
        for i in range(20):
            alpha_hex = format(max(2, 8 - i), '02x')
            color = HexColor(f"#0000{alpha_hex}")
            c.setFillColor(color)
            band_h = self.height / 20
            c.rect(0, i * band_h, self.width, band_h, fill=1, stroke=0)

        # Subtle glow at top
        for r in range(60, 0, -2):
            alpha = int(3 * (60 - r) / 60)
            c.setFillColor(HexColor("#00ff88"))
            c.setFillAlpha(alpha / 100)
            c.circle(cx, self.height - 50, r, fill=1, stroke=0)
        c.setFillAlpha(1)

        # Circuit decoration
        self._draw_circuit_lines(c, circuit_color)

        # ── Outer border ──
        c.setStrokeColor(primary_dim)
        c.setLineWidth(2.5)
        c.roundRect(25, 25, self.width - 50, self.height - 50, 8, fill=0)
        c.setStrokeColor(secondary)
        c.setLineWidth(0.8)
        c.roundRect(33, 33, self.width - 66, self.height - 66, 6, fill=0)

        # Corner brackets
        self._draw_decorative_corners(c, 40, self.height - 40, self.width - 40, 40, gold, length=30)

        # ── Top Bar: Logo + Program ──
        c.setFillColor(dark3)
        c.rect(40, self.height - 82, self.width - 80, 38, fill=1, stroke=0)
        c.setStrokeColor(primary)
        c.setLineWidth(0.8)
        c.line(40, self.height - 82, self.width - 40, self.height - 82)

        c.setFillColor(primary)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(56, self.height - 68, "DARK WEB MONITOR")
        c.setFillColor(gold)
        c.setFont("Helvetica", 8)
        c.drawRightString(self.width - 56, self.height - 66, "CYBERSECURITY AWARENESS PROGRAM")

        # ── Shield icon ──
        shield_size = 32
        self._draw_shield_icon(c, cx - shield_size / 2, self.height - 128, shield_size, dark2, primary)
        c.setStrokeColor(primary)
        c.setLineWidth(2)
        sx = cx - 5
        sy = self.height - 110
        c.line(sx, sy, sx + 5, sy - 7)
        c.line(sx + 5, sy - 7, sx + 13, sy + 7)

        # ── Title ──
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 32)
        c.drawCentredString(cx, self.height - 165, "CERTIFICATE")
        c.setFillColor(secondary)
        c.setFont("Helvetica", 14)
        c.drawCentredString(cx, self.height - 184, "OF   COMPLETION")

        # Decorative line
        line_w = 200
        c.setStrokeColor(primary)
        c.setLineWidth(0.8)
        c.line(cx - line_w, self.height - 194, cx - 30, self.height - 194)
        c.line(cx + 30, self.height - 194, cx + line_w, self.height - 194)
        # Center diamond
        c.setFillColor(primary)
        p = c.beginPath()
        dy = self.height - 194
        p.moveTo(cx, dy + 4)
        p.lineTo(cx + 4, dy)
        p.lineTo(cx, dy - 4)
        p.lineTo(cx - 4, dy)
        p.close()
        c.drawPath(p, fill=1, stroke=0)

        # ── "This is to certify that" ──
        c.setFillColor(light_gray)
        c.setFont("Helvetica-Oblique", 12)
        c.drawCentredString(cx, self.height - 220, "This is to certify that")

        # ── Participant Name ──
        name_text = result.participant_name.upper()
        c.setFillColor(gold)
        c.setFont("Helvetica-Bold", 30)
        c.drawCentredString(cx, self.height - 255, name_text)

        # Gold line under name
        name_w = c.stringWidth(name_text, "Helvetica-Bold", 30)
        half_nw = max(name_w / 2, 80) + 20
        c.setStrokeColor(gold_dim)
        c.setLineWidth(1.2)
        c.line(cx - half_nw, self.height - 267, cx + half_nw, self.height - 267)

        # ── Description ──
        c.setFillColor(white)
        c.setFont("Helvetica", 11)
        c.drawCentredString(cx, self.height - 290,
                           "has successfully completed the Cybersecurity Awareness Quiz")
        c.setFillColor(light_gray)
        c.setFont("Helvetica", 10)
        c.drawCentredString(cx, self.height - 306,
                           "demonstrating proficiency in cybersecurity fundamentals, threat awareness, and security best practices.")

        # ── Score Panel ──
        panel_w = 380
        panel_h = 44
        panel_x = cx - panel_w / 2
        panel_y = self.height - 365

        c.setFillColor(dark3)
        c.setStrokeColor(primary_dim if result.passed else HexColor("#ff6600"))
        c.setLineWidth(1.2)
        c.roundRect(panel_x, panel_y, panel_w, panel_h, 6, fill=1)

        # Three columns inside panel: Score | Status | Date
        third = panel_w / 3

        # Vertical dividers
        c.setStrokeColor(HexColor("#2a2a4e"))
        c.setLineWidth(0.6)
        c.line(panel_x + third, panel_y + 6, panel_x + third, panel_y + panel_h - 6)
        c.line(panel_x + 2 * third, panel_y + 6, panel_x + 2 * third, panel_y + panel_h - 6)

        # Score
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 18)
        c.drawCentredString(panel_x + third / 2, panel_y + 18, f"{result.percentage}%")
        c.setFillColor(mid_gray)
        c.setFont("Helvetica", 7)
        c.drawCentredString(panel_x + third / 2, panel_y + 6, f"SCORE ({result.score}/{result.total})")

        # Status
        status_text = "PASSED" if result.passed else "NOT PASSED"
        status_color = primary if result.passed else HexColor("#ff5555")
        c.setFillColor(status_color)
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(panel_x + third * 1.5, panel_y + 18, status_text)
        c.setFillColor(mid_gray)
        c.setFont("Helvetica", 7)
        c.drawCentredString(panel_x + third * 1.5, panel_y + 6, "STATUS")

        # Date
        c.setFillColor(white)
        c.setFont("Helvetica", 10)
        c.drawCentredString(panel_x + third * 2.5, panel_y + 18, result.completion_time)
        c.setFillColor(mid_gray)
        c.setFont("Helvetica", 7)
        c.drawCentredString(panel_x + third * 2.5, panel_y + 6, "DATE ISSUED")

        # ── Bottom Bar ──
        c.setFillColor(dark3)
        c.rect(40, 40, self.width - 80, 38, fill=1, stroke=0)
        c.setStrokeColor(primary)
        c.setLineWidth(0.8)
        c.line(40, 78, self.width - 40, 78)

        # Certificate ID (left)
        cert_id = certificate_id or f"CERT-{result.quiz_id.upper()}"
        c.setFillColor(mid_gray)
        c.setFont("Helvetica", 8)
        c.drawString(56, 56, f"Certificate ID: {cert_id}")

        # Center footer
        c.setFillColor(secondary)
        c.setFont("Helvetica-Oblique", 8)
        c.drawCentredString(cx, 56, "Dark Web Monitor  |  Cybersecurity Awareness Program")

        # Date (right)
        c.setFillColor(mid_gray)
        c.setFont("Helvetica", 8)
        c.drawRightString(self.width - 56, 56, f"Issued: {result.completion_time}")

        # ── Signature line (centered, above bottom bar) ──
        sig_y = 100
        sig_w = 120
        c.setStrokeColor(HexColor("#404060"))
        c.setLineWidth(0.8)
        c.line(cx - sig_w / 2, sig_y, cx + sig_w / 2, sig_y)
        c.setFillColor(light_gray)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(cx, sig_y - 12, "Dark Web Monitor")
        c.setFillColor(mid_gray)
        c.setFont("Helvetica", 7)
        c.drawCentredString(cx, sig_y - 22, "PROGRAM DIRECTOR")

        c.save()
        buffer.seek(0)
        return buffer.getvalue()


if __name__ == "__main__":
    # Test quiz
    quiz = CybersecurityQuiz()
    session = quiz.start_quiz()
    print(f"Quiz started: {session['quiz_id']}")
    print(f"Questions: {session['total_questions']}")
    
    # Simulate answers (all correct for testing)
    answers = {}
    for q in quiz.active_quizzes[session['quiz_id']]:
        answers[q.id] = q.correct_answer
    
    result = quiz.submit_quiz(session['quiz_id'], "Test User", "test@example.com", answers)
    print(f"Score: {result.score}/{result.total} ({result.percentage}%)")
    print(f"Passed: {result.passed}")
    
    # Generate certificate
    generator = CertificateGenerator()
    pdf_bytes = generator.generate(result)
    with open("test_certificate.pdf", "wb") as f:
        f.write(pdf_bytes)
    print("Certificate generated: test_certificate.pdf")
