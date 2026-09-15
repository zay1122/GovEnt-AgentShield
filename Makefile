.PHONY: install test demo benchmark dashboard api verify

install:
	python -m pip install -r requirements.txt

test:
	python -m unittest discover -s tests -p "test_*.py" -v

demo:
	python src/runtime_controller.py --demo
	python src/control_aggregator.py

benchmark:
	python evaluation/generate_benchmark.py
	python evaluation/run_input_benchmark.py
	python evaluation/run_tool_benchmark.py
	python evaluation/run_skill_benchmark.py

dashboard:
	python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501

api:
	python src/api.py

verify:
	python scripts/verify_release.py
