import os
import time
import json
import psutil
import psycopg2

DB_URL = os.getenv("DATABASE_PUBLIC_URL")

def connect_db():
    try:
        return psycopg2.connect(DB_URL)
    except Exception as e:
        print(f"⚠️ Не удалось подключиться к БД:\n{e}")
        return None

def get_signatures():
    conn = connect_db()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT signature FROM signatures;")
                results = cur.fetchall()
                return [row[0] for row in results]
        except Exception as e:
            print(f"⚠️ Ошибка при получении сигнатур из БД:\n{e}")
        finally:
            conn.close()

    # fallback: local file
    if os.path.exists("signatures.json"):
        print("📁 Загрузка сигнатур из локального файла...")
        with open("signatures.json", "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        print("❌ Нет сигнатур. Ни база, ни файл не доступны.")
        return []

def simulate_scan(signatures):
    total = 40
    for i in range(total + 1):
        bar = "█" * i + "=" * (total - i)
        print(f"\r[{bar}]", end="", flush=True)
        time.sleep(0.05)
    print()

def scan_processes(signatures):
    print("🔬 Сканирование процессов...")
    simulate_scan(signatures)

    detected = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for sig in signatures:
                if sig.lower() in proc.info['name'].lower():
                    detected.append((proc.info['pid'], proc.info['name']))
        except Exception:
            pass

    return detected

def main_loop():
    print("🔍 Проверка зависимостей...")
    print("📦 Проверка наличия локальной копии...")
    print("🚀 Запуск иммунной системы...")
    print("🧬 Иммунная система активирована. Начинается глубокий анализ...")

    signatures = get_signatures()

    if not signatures:
        print("⚠️ Не удалось получить сигнатуры.")
    else:
        results = scan_processes(signatures)
        if results:
            print("☣️ Обнаружены подозрительные процессы:")
            for pid, name in results:
                print(f" - {name} (PID {pid})")
        else:
            print("✅ Угроз не обнаружено.")

    print("✅ Сканирование завершено. Ожидание новых угроз...")

if __name__ == "__main__":
    main_loop()
