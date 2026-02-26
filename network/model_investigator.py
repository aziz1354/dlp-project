#!/usr/bin/env python3
import joblib
import numpy as np
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ModelInvestigator:
    def __init__(self, models_base_path='/root/dlp_project/ai_models'):
        self.models_base_path = Path(models_base_path)
        self.model_contexts = ['dns', 'http', 'general']

    def load_model(self, context):
        """
        Load a joblib model from a specific context
        
        Args:
            context (str): Model context (dns, http, or general)
        
        Returns:
            Loaded model or None
        """
        model_path = self.models_base_path / context / 'model.joblib'
        
        try:
            model = joblib.load(model_path)
            logger.info(f"Successfully loaded {context} model from {model_path}")
            return model
        except Exception as e:
            logger.error(f"Error loading {context} model: {e}")
            return None

    def investigate_model(self, context):
        """
        Investigate the properties of a loaded model
        
        Args:
            context (str): Model context (dns, http, or general)
        
        Returns:
            dict: Model investigation results
        """
        model = self.load_model(context)
        if not model:
            return {}

        results = {
            'type': type(model).__name__,
            'context': context
        }

        # Common scikit-learn model investigations
        try:
            # Check for predict method
            if hasattr(model, 'predict'):
                results['has_predict'] = True
            
            # Check for predict_proba method
            if hasattr(model, 'predict_proba'):
                results['has_predict_proba'] = True
            
            # For classification models
            if hasattr(model, 'classes_'):
                results['classes'] = list(model.classes_)
        except Exception as e:
            logger.error(f"Error investigating {context} model: {e}")

        return results

    def investigate_all_models(self):
        """
        Investigate all models
        
        Returns:
            dict: Investigation results for all models
        """
        all_results = {}
        for context in self.model_contexts:
            all_results[context] = self.investigate_model(context)
        return all_results

def main():
    investigator = ModelInvestigator()
    results = investigator.investigate_all_models()
    
    print("Model Investigation Results:")
    import json
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
