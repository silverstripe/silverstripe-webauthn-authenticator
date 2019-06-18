import PropTypes from 'prop-types';

export default PropTypes.shape({
  challenge: PropTypes.string.isRequired,
  rpId: PropTypes.string,
  userVerification: PropTypes.string,
  allowCredentials: PropTypes.arrayOf(PropTypes.shape({
    id: PropTypes.string.isRequired,
    type: PropTypes.string.isRequired,
    transports: PropTypes.arrayOf(PropTypes.string),
  })),
  extensions: PropTypes.Object,
  timeout: PropTypes.number,
});
