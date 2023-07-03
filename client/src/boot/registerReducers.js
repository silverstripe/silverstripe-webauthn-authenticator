import Injector from 'lib/Injector'; // eslint-disable-line
import webauthnAvailableReducer from 'state/webauthnAvailableReducer';

export default () => {
  // See MFA "method availability reducer" naming conventions in the documentation
  Injector.reducer.register('web-authnAvailability', webauthnAvailableReducer);
};
