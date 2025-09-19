"""Basic tests for PhishNet components."""

import pytest
from app.ml.feature_extraction import FeatureExtractor
from app.ml.classical_models import ClassicalModel
from app.core.security import get_password_hash, verify_password


def test_feature_extraction():
    """Test feature extraction functionality."""
    extractor = FeatureExtractor()
    
    # Test email content
    email_content = """
    URGENT: Your account has been suspended!
    Click here to verify your identity: http://bit.ly/suspicious-link
    Please provide your password and credit card information.
    """
    
    features = extractor.extract_features(
        email_content,
        subject="URGENT: Account Suspended",
        sender="noreply@bank.com"
    )
    
    # Check that features are extracted
    assert 'suspicious_keyword_count' in features
    assert 'url_count' in features
    assert 'sentiment_polarity' in features
    assert 'has_javascript' in features
    
    # Check specific values
    assert features['suspicious_keyword_count'] > 0
    assert features['url_count'] > 0
    assert features['has_urls'] == True
    
    # Test feature vector
    feature_vector = extractor.get_feature_vector(features)
    assert len(feature_vector) > 0
    assert all(isinstance(x, (int, float)) for x in feature_vector)


def test_password_hashing():
    """Test password hashing functionality."""
    password = "test_password_123"
    
    # Hash password
    hashed = get_password_hash(password)
    assert hashed != password
    assert len(hashed) > 0
    
    # Verify password
    assert verify_password(password, hashed) == True
    assert verify_password("wrong_password", hashed) == False


def test_classical_model():
    """Test classical model functionality."""
    model = ClassicalModel("random_forest")
    
    # Test model initialization
    assert model.model is not None
    assert model.model_type == "random_forest"
    assert model.is_trained == False
    
    # Test with dummy data (model won't be trained, but should handle input)
    features = [0.1, 0.2, 0.3, 0.4, 0.5] * 6  # 30 features
    try:
        # This should raise an error since model isn't trained
        model.predict_single(features)
        assert False, "Should have raised an error for untrained model"
    except ValueError:
        # Expected behavior
        pass


def test_feature_extractor_suspicious_keywords():
    """Test suspicious keyword detection."""
    extractor = FeatureExtractor()
    
    # Test with suspicious content
    suspicious_content = "URGENT account suspended verify login password bank credit card"
    features = extractor.extract_features(suspicious_content)
    
    assert features['suspicious_keyword_count'] > 0
    
    # Test with legitimate content
    legitimate_content = "Hello, this is a normal email about our meeting tomorrow."
    features = extractor.extract_features(legitimate_content)
    
    assert features['suspicious_keyword_count'] == 0


def test_feature_extractor_url_analysis():
    """Test URL analysis functionality."""
    extractor = FeatureExtractor()
    
    # Test with shortened URLs
    content_with_shortened = "Check this link: http://bit.ly/suspicious"
    features = extractor.extract_features(content_with_shortened)
    
    assert features['url_count'] > 0
    assert features['shortened_url_count'] > 0
    
    # Test with normal URLs
    content_with_normal = "Visit our website: https://example.com"
    features = extractor.extract_features(content_with_normal)
    
    assert features['url_count'] > 0
    assert features['shortened_url_count'] == 0


if __name__ == "__main__":
    # Run tests
    test_feature_extraction()
    test_password_hashing()
    test_classical_model()
    test_feature_extractor_suspicious_keywords()
    test_feature_extractor_url_analysis()
    print("All basic tests passed!")


