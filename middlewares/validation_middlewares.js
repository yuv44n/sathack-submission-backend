/**
 * Sanitize string input to prevent XSS attacks
 */
const sanitizeString = (str, maxLength = 10000) => {
  if (typeof str !== 'string') return '';
  // Remove potentially dangerous characters and limit length
  return str
    .trim()
    .slice(0, maxLength)
    .replace(/[<>]/g, ''); // Remove < and > to prevent HTML injection
};

/**
 * Validation middleware for team submission
 * Only validates: githubLink, pptLink, videoLink, description
 * Team and leader data are fetched from Firestore
 */
export const validateSubmission = (req, res, next) => {
  try {
    const {
      githubLink,
      pptLink,
      videoLink,
      description,
    } = req.body;

    const errors = [];
    const MAX_URL_LENGTH = 2048;
    const MAX_DESCRIPTION_LENGTH = 5000;

    // Validate githubLink
    if (!githubLink || typeof githubLink !== 'string' || githubLink.trim().length === 0) {
      errors.push('githubLink is required and must be a non-empty string');
    } else {
      const trimmed = githubLink.trim();
      if (trimmed.length > MAX_URL_LENGTH) {
        errors.push(`githubLink must be less than ${MAX_URL_LENGTH} characters`);
      } else {
        // Validate URL format
        try {
          const url = new URL(trimmed);
          // Ensure it's http or https
          if (!['http:', 'https:'].includes(url.protocol)) {
            errors.push('githubLink must use http or https protocol');
          }
        } catch (error) {
          errors.push('githubLink must be a valid URL');
        }
      }
    }

    // Validate pptLink
    if (!pptLink || typeof pptLink !== 'string' || pptLink.trim().length === 0) {
      errors.push('pptLink is required and must be a non-empty string');
    } else {
      const trimmed = pptLink.trim();
      if (trimmed.length > MAX_URL_LENGTH) {
        errors.push(`pptLink must be less than ${MAX_URL_LENGTH} characters`);
      } else {
        // Validate URL format
        try {
          const url = new URL(trimmed);
          if (!['http:', 'https:'].includes(url.protocol)) {
            errors.push('pptLink must use http or https protocol');
          }
        } catch (error) {
          errors.push('pptLink must be a valid URL');
        }
      }
    }

    // Validate videoLink
    if (!videoLink || typeof videoLink !== 'string' || videoLink.trim().length === 0) {
      errors.push('videoLink is required and must be a non-empty string');
    } else {
      const trimmed = videoLink.trim();
      if (trimmed.length > MAX_URL_LENGTH) {
        errors.push(`videoLink must be less than ${MAX_URL_LENGTH} characters`);
      } else {
        // Validate URL format
        try {
          const url = new URL(trimmed);
          if (!['http:', 'https:'].includes(url.protocol)) {
            errors.push('videoLink must use http or https protocol');
          }
        } catch (error) {
          errors.push('videoLink must be a valid URL');
        }
      }
    }

    // Validate description
    if (!description || typeof description !== 'string' || description.trim().length === 0) {
      errors.push('description is required and must be a non-empty string');
    } else {
      const trimmed = description.trim();
      if (trimmed.length > MAX_DESCRIPTION_LENGTH) {
        errors.push(`description must be less than ${MAX_DESCRIPTION_LENGTH} characters`);
      }
    }

    // If there are validation errors, return them
    if (errors.length > 0) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors,
      });
    }

    // Sanitize and trim all fields
    req.body.githubLink = sanitizeString(githubLink, MAX_URL_LENGTH);
    req.body.pptLink = sanitizeString(pptLink, MAX_URL_LENGTH);
    req.body.videoLink = sanitizeString(videoLink, MAX_URL_LENGTH);
    req.body.description = sanitizeString(description, MAX_DESCRIPTION_LENGTH);

    next();
  } catch (error) {
    console.error('[VALIDATION MIDDLEWARE ERROR]:', error);
    return res.status(500).json({
      error: 'Internal server error during validation',
    });
  }
};

