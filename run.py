"""
Development entry-point.
Run with:  python run.py
Production: gunicorn -w 4 -b 0.0.0.0:5000 "run:app"
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
