# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m

from flask import Flask, render_template, request, jsonify, session
import openai
import base64
import os
import requests
from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from tempfile import NamedTemporaryFile
from werkzeug.utils import secure_filename
from asyncio import to_thread
import asyncio


UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "secret"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "SimpleCache"  # In-memory cache for development
app.config["CACHE_DEFAULT_TIMEOUT"] = 60 * 60  # 1 hour cache timeout
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

brains = {}


@app.route("/")
def index():
    _lineaje_payload = "index.html"
    # LINEAJE: enforce() `_lineaje_payload` at html->user_interface data_egress — scan flagged AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:0850b8d863ad4c83c1a483276137f13d3a73f16f9387e37e5c68ee52ae0e73fd'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0850b8d863ad4c83c1a483276137f13d3a73f16f9387e37e5c68ee52ae0e73fd', phase='data_egress', boundary={'source': 'html', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='html', destination_type='user_interface')
    _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='text/html')
    return render_template(_lineaje_payload)


def run_in_event_loop(func, *args, **kwargs):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if asyncio.iscoroutinefunction(func):
        result = loop.run_until_complete(func(*args, **kwargs))
    else:
        result = func(*args, **kwargs)
    loop.close()
    # LINEAJE: enforce() `result` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:ffcbc0cc7116dfd3069669ce4b02abc06e13efebed2eef28bb263a3fa6709777'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ffcbc0cc7116dfd3069669ce4b02abc06e13efebed2eef28bb263a3fa6709777', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    result = _gr_client.enforce(_gr_site, result, content_type='text/plain')
    return result


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
async def upload_file():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400
    if not (file and file.filename and allowed_file(file.filename)):
        return "Invalid file type", 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    _lineaje_payload = f"File uploaded and saved at: {filepath}"
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)

    _lineaje_payload = "Creating brain instance..."
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:f93c73f830a174be772f85b2a54888b9e815ecd2a79a79c6cb89d0e6052b3ebd'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f93c73f830a174be772f85b2a54888b9e815ecd2a79a79c6cb89d0e6052b3ebd', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)

    brain: Brain = await to_thread(
        run_in_event_loop, Brain.from_files, name="user_brain", file_paths=[filepath]
    )

    # Store brain instance in cache
    session_id = session.sid if hasattr(session, "sid") else os.urandom(16).hex()
    session["session_id"] = session_id
    # cache.set(session_id, brain)  # Store the brain instance in the cache
    brains[session_id] = brain
    _lineaje_payload = f"Brain instance created and stored in cache for session ID: {session_id}"
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:1b14b7829a142ce941d1098f5d4fc53ab8795e231140002bd8fdbbf0fe4ad7af'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1b14b7829a142ce941d1098f5d4fc53ab8795e231140002bd8fdbbf0fe4ad7af', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)

    _lineaje_payload = {"message": "Brain created successfully"}
    # LINEAJE: enforce() `_lineaje_payload` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='text/plain'))
    return jsonify(_lineaje_payload)


@app.route("/ask", methods=["POST"])
async def ask():
    if "audio_data" not in request.files:
        return "Missing audio data", 400

    # Retrieve the brain instance from the cache using the session ID
    session_id = session.get("session_id")
    if not session_id:
        return "Session ID not found. Upload a file first.", 400

    brain = brains.get(session_id)
    if not brain:
        return "Brain instance not found in dict. Upload a file first.", 400

    _lineaje_payload = "Brain instance loaded from cache."
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:b1aee21cc2efac7fc74cc55597f50d8d174d0e8505c2b41d8cc4fe69dfa928a6'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b1aee21cc2efac7fc74cc55597f50d8d174d0e8505c2b41d8cc4fe69dfa928a6', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)

    _lineaje_payload = "Speech to text..."
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:12357767cdadecd417245d788b24511aa36108c23208adccb6c96ccfb26e64f5'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:12357767cdadecd417245d788b24511aa36108c23208adccb6c96ccfb26e64f5', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)
    audio_file = request.files["audio_data"]
    transcript = transcribe_audio_file(audio_file)
    # LINEAJE: enforce() `transcript` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:0bc844c8c9eb7ab37fbb033fd4081b7b023e6e40321ca4a8a8f54ef1c1dac237'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0bc844c8c9eb7ab37fbb033fd4081b7b023e6e40321ca4a8a8f54ef1c1dac237', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    transcript = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, transcript, content_type='application/json'))
    print("Transcript result: ", transcript)

    _lineaje_payload = "Getting response..."
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:3f268ec6ce42fa6f0a5c56bd56f70f4f575536b79b493e0df57a5b734b6f2122'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3f268ec6ce42fa6f0a5c56bd56f70f4f575536b79b493e0df57a5b734b6f2122', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)
    quivr_response = await to_thread(run_in_event_loop, brain.ask, transcript)

    _lineaje_payload = "Text to speech..."
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:baf5d2bdd2057943b5c5b47f52b4af787dc2cecdb58cc3bab6ee73e2cfa26770'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:baf5d2bdd2057943b5c5b47f52b4af787dc2cecdb58cc3bab6ee73e2cfa26770', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)
    audio_base64 = synthesize_speech(quivr_response.answer)

    _lineaje_payload = "Done"
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:e6d9f67066c351c6fccd2b2c093f0069f0d3a458c1e68c7b7f8c92ead77a07c4'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e6d9f67066c351c6fccd2b2c093f0069f0d3a458c1e68c7b7f8c92ead77a07c4', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    print(_lineaje_payload)
    _lineaje_payload = {"audio_base64": audio_base64}
    # LINEAJE: enforce() `_lineaje_payload` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:7932e7672624b6773cbd554abfaa28c9f30f7ab524f0c4b0151979e652e8525e'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7932e7672624b6773cbd554abfaa28c9f30f7ab524f0c4b0151979e652e8525e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='text/plain'))
    return jsonify(_lineaje_payload)


def transcribe_audio_file(audio_file):
    with NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio_file:
        audio_file.save(temp_audio_file)
        temp_audio_file_path = temp_audio_file.name

    try:
        with open(temp_audio_file_path, "rb") as f:
            transcript_response = openai.audio.transcriptions.create(
                model="whisper-1", file=f
            )
        transcript = transcript_response.text
    finally:
        os.unlink(temp_audio_file_path)

    # LINEAJE: enforce() `transcript` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:45d3f7815a6db56c52bfb948a2a4b8b25a763e9f475f49d8e92bd33bc52600b6'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:45d3f7815a6db56c52bfb948a2a4b8b25a763e9f475f49d8e92bd33bc52600b6', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    transcript = _gr_client.enforce(_gr_site, transcript, content_type='text/plain')
    return transcript


def synthesize_speech(text):
    speech_response = openai.audio.speech.create(
        model="tts-1", voice="nova", input=text
    )
    audio_content = speech_response.content
    audio_base64 = base64.b64encode(audio_content).decode("utf-8")
    # LINEAJE: enforce() `audio_base64` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:a9c6367d4a467e0baab232b2cad6d3af14b1edb1e01b63fe4f12c646492c79a2'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a9c6367d4a467e0baab232b2cad6d3af14b1edb1e01b63fe4f12c646492c79a2', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    audio_base64 = _gr_client.enforce(_gr_site, audio_base64, content_type='text/plain')
    return audio_base64


if __name__ == "__main__":
    app.run(debug=True)
