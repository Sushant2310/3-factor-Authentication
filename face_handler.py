"""
Face recognition handler using OpenCV DNN - reliable face detection and basic recognition.
Uses OpenCV's DNN face detector and simple feature extraction for recognition.
"""

import os
import numpy as np
import cv2
import logging
from typing import Tuple, Optional, List
from numpy.typing import NDArray
from sklearn.metrics.pairwise import cosine_similarity

from data_manager import store_face_encoding, get_face_encoding

logger = logging.getLogger(__name__)

# Global OpenCV DNN model
_face_net = None

def _load_face_model():
    """Load OpenCV DNN face detection model"""
    global _face_net
    if _face_net is None:
        try:
            # Use OpenCV's DNN face detector
            model_file = "res10_300x300_ssd_iter_140000.caffemodel"
            config_file = "deploy.prototxt"

            # Use local models in the current directory
            model_path = os.path.join(os.path.dirname(__file__), model_file)
            config_path = os.path.join(os.path.dirname(__file__), config_file)

            if not os.path.exists(model_path):
                logger.warning(f"Model file not found: {model_path}. Face recognition will be disabled.")
                _face_net = None
                return None

            if not os.path.exists(config_path):
                logger.warning(f"Config file not found: {config_path}. Face recognition will be disabled.")
                _face_net = None
                return None

            _face_net = cv2.dnn.readNetFromCaffe(config_path, model_path)
            logger.info("OpenCV DNN face detection model loaded successfully")

        except Exception as e:
            logger.warning(f"Failed to load OpenCV DNN model: {e}. Face recognition will be disabled.")
            _face_net = None
            return None
    return _face_net

def detect_faces(rgb: NDArray[np.uint8]) -> List[Tuple[int, int, int, int]]:
    """
    Detect faces using OpenCV DNN.
    Returns list of bounding boxes in (top, right, bottom, left) format.
    """
    boxes = []

    try:
        net = _load_face_model()
        h, w = rgb.shape[:2]

        # Prepare blob for DNN
        blob = cv2.dnn.blobFromImage(rgb, 1.0, (300, 300), (104.0, 177.0, 123.0))
        net.setInput(blob)
        detections = net.forward()

        for i in range(detections.shape[2]):
            confidence = detections[0, 0, i, 2]
            if confidence > 0.5:  # Confidence threshold
                box = detections[0, 0, i, 3:7] * np.array([w, h, w, h])
                x_min, y_min, x_max, y_max = box.astype(int)

                # Ensure coordinates are within image bounds
                x_min = max(0, x_min)
                y_min = max(0, y_min)
                x_max = min(w, x_max)
                y_max = min(h, y_max)

                # Convert to (top, right, bottom, left) format
                boxes.append((y_min, x_max, y_max, x_min))

    except Exception as e:
        logger.warning(f"Face detection error: {e}")

    return boxes


def validate_face_framing(
    face: Tuple[int, int, int, int],
    image_shape: Tuple[int, ...]
) -> Tuple[bool, str]:
    """
    Validate that a detected face is fully visible and reasonably centered.
    Expects face in (top, right, bottom, left) format.
    """
    image_height, image_width = image_shape[:2]
    top, right, bottom, left = face

    face_width = max(0, right - left)
    face_height = max(0, bottom - top)
    if face_width == 0 or face_height == 0:
      return False, "Invalid face region detected. Please try again."

    face_area_ratio = (face_width * face_height) / float(image_width * image_height)
    if face_area_ratio < 0.08:
        return False, "Move closer so your full face fills more of the frame."

    edge_margin_x = image_width * 0.06
    edge_margin_y = image_height * 0.08
    if left <= edge_margin_x or right >= image_width - edge_margin_x:
        return False, "Center your face horizontally so both sides are fully visible."
    if top <= edge_margin_y or bottom >= image_height - edge_margin_y:
        return False, "Keep your full face inside the frame with some space above and below."

    face_center_x = (left + right) / 2.0
    face_center_y = (top + bottom) / 2.0
    center_offset_x = abs(face_center_x - (image_width / 2.0)) / image_width
    center_offset_y = abs(face_center_y - (image_height / 2.0)) / image_height

    if center_offset_x > 0.18:
        return False, "Move your face toward the center of the camera."
    if center_offset_y > 0.18:
        return False, "Raise or lower the camera so your face is centered."

    face_aspect_ratio = face_height / float(face_width)
    if face_aspect_ratio < 0.9 or face_aspect_ratio > 1.8:
        return False, "Look straight at the camera and keep your full face visible."

    return True, "Full face detected."

def detect_liveness(image_array: NDArray[np.uint8]) -> Tuple[bool, str]:
    """
    Basic liveness detection using image analysis.
    Checks for image properties that indicate a live capture vs photo.
    """
    try:
        # Detect faces first
        faces = detect_faces(image_array)
        if not faces:
            return False, "No face detected"

        # Check 1: Face size relative to image
        height, width = image_array.shape[:2]
        face = faces[0]
        top, right, bottom, left = face
        framing_ok, framing_message = validate_face_framing(face, image_array.shape)
        if not framing_ok:
            return False, framing_message

        face_width = max(0, right - left)
        face_height = max(0, bottom - top)
        face_area = face_width * face_height
        image_area = height * width
        face_ratio = face_area / image_area

        if face_ratio < 0.01:  # Face too small
            return False, "Face too small. Please move closer to camera."

        # Check 2: Image sharpness/blur detection
        # Convert to grayscale and compute Laplacian variance
        gray = cv2.cvtColor(image_array, cv2.COLOR_RGB2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()

        if laplacian_var < 100:  # Too blurry, might be a photo
            return False, "Image appears blurry. Please ensure clear focus."

        # Check 3: Color distribution (photos might have unnatural colors)
        if image_array.shape[2] == 3:
            # Check if image has natural color distribution
            hist_r = cv2.calcHist([image_array], [0], None, [256], [0, 256])
            hist_g = cv2.calcHist([image_array], [1], None, [256], [0, 256])
            hist_b = cv2.calcHist([image_array], [2], None, [256], [0, 256])

            # Simple check: ensure all channels have reasonable distribution
            r_mean = np.mean(hist_r)
            g_mean = np.mean(hist_g)
            b_mean = np.mean(hist_b)

            if r_mean < 10 or g_mean < 10 or b_mean < 10:
                return False, "Image colors appear unnatural."

        return True, "Liveness confirmed with basic image analysis."

    except Exception as e:
        logger.warning(f"Liveness detection error: {e}")
        return False, f"Liveness check error: {e}"

def extract_face_features(face_image: NDArray[np.uint8]) -> NDArray[np.float32]:
    """
    Extract basic features from face using simple image processing.
    This is a simplified approach that creates a feature vector from image statistics.
    """
    return _extract_face_features(face_image)

def _extract_face_features(face_image: NDArray[np.uint8]) -> NDArray[np.float32]:
    """
    Extract basic features from face using simple image processing.
    This is a simplified approach that creates a feature vector from image statistics.
    """
    try:
        # Convert to grayscale
        gray = cv2.cvtColor(face_image, cv2.COLOR_RGB2GRAY)

        # Resize to fixed size for consistent features
        resized = cv2.resize(gray, (64, 64))

        # Extract various statistical features
        features = []

        # Pixel intensity histogram (16 bins)
        hist = cv2.calcHist([resized], [0], None, [16], [0, 256])
        hist = hist.flatten() / np.sum(hist)  # Normalize
        features.extend(hist)

        # Edge detection features
        edges = cv2.Canny(resized, 100, 200)
        edge_hist = cv2.calcHist([edges], [0], None, [8], [0, 256])
        edge_hist = edge_hist.flatten() / np.sum(edge_hist)
        features.extend(edge_hist)

        # Local binary patterns (simplified)
        # Create a simple texture descriptor
        texture_features = []
        for i in range(0, 64, 16):
            for j in range(0, 64, 16):
                patch = resized[i:i+16, j:j+16]
                texture_features.extend([
                    np.mean(patch),
                    np.std(patch),
                    np.var(patch)
                ])
        features.extend(texture_features)

        return np.array(features, dtype=np.float32)

    except Exception as e:
        logger.error(f"Feature extraction error: {e}")
        raise

def process_face_image(image_array: NDArray[np.uint8]) -> NDArray[np.float32]:
    """
    Detect single face and return feature vector using OpenCV.
    Raises ValueError with descriptive message if face processing fails.
    """
    if image_array is None:
        raise ValueError("No image provided")

    # Convert to numpy array if not already
    if not isinstance(image_array, np.ndarray):
        image_array = np.array(image_array)

    # Ensure uint8 and proper shape
    rgb = image_array.astype(np.uint8) if image_array.dtype != np.uint8 else image_array
    if rgb.ndim == 2:
        rgb = cv2.cvtColor(rgb, cv2.COLOR_GRAY2RGB)
    elif rgb.shape[2] == 4:
        rgb = cv2.cvtColor(rgb, cv2.COLOR_RGBA2RGB)
    elif rgb.shape[2] == 3:
        # Assume BGR to RGB for OpenCV compatibility
        rgb = cv2.cvtColor(rgb, cv2.COLOR_BGR2RGB)

    rgb = np.ascontiguousarray(rgb).copy()

    # Validate image
    if rgb.ndim != 3 or rgb.shape[2] != 3 or rgb.dtype != np.uint8:
        raise ValueError(f"Image must be 3-channel 8-bit RGB. Got shape={rgb.shape}, dtype={rgb.dtype}")

    # Check if face detection is available
    if _face_net is None:
        raise ValueError("Face recognition is not available. Required model files are missing.")

    # Detect faces
    try:
        faces = detect_faces(rgb)

        if not faces:
            raise ValueError("No face detected. Please ensure your face is clearly visible.")

        if len(faces) > 1:
            raise ValueError("Multiple faces detected. Please ensure only one person is in view.")

        # Extract face region
        face_box = faces[0]
        framing_ok, framing_message = validate_face_framing(face_box, rgb.shape)
        if not framing_ok:
            raise ValueError(framing_message)

        top, right, bottom, left = face_box
        face_image = rgb[top:bottom, left:right]

        if face_image.size == 0:
            raise ValueError("Invalid face region detected.")

        # Extract features
        features = _extract_face_features(face_image)

        return features

    except Exception as e:
        raise ValueError(f"Face processing failed: {e}")

def encode_face(username: str, image_array: NDArray[np.uint8]) -> bool:
    """Encode and store face features for a user"""
    try:
        features = process_face_image(image_array)
        store_face_encoding(username, features)
        logger.info(f"Face encoded successfully for user: {username}")
        return True
    except Exception as e:
        logger.error(f"Face encoding failed for user {username}: {e}")
        raise

def verify_face(username: str, image_array: NDArray[np.uint8], threshold: float = 0.7) -> bool:
    """
    Verify face against stored features using cosine similarity.
    Threshold: Higher values are more strict (default 0.7 for basic features)
    """
    try:
        stored = get_face_encoding(username)
        if stored is None:
            raise ValueError("No face registered for this user.")

        features = process_face_image(image_array)

        # Calculate cosine similarity
        similarity = cosine_similarity([stored], [features])[0][0]

        # Basic features: similarity > 0.7 typically indicates match
        is_match = similarity > threshold

        logger.info(f"Face verification for {username}: similarity={similarity:.3f}, match={is_match}")

        return is_match

    except Exception as e:
        logger.error(f"Face verification failed for user {username}: {e}")
        raise

# Initialize model on import
_load_face_model()
logger.info("OpenCV DNN face recognition system initialized successfully")
