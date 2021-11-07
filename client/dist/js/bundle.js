!function(e){function t(r){if(n[r])return n[r].exports;var a=n[r]={i:r,l:!1,exports:{}};return e[r].call(a.exports,a,a.exports,t),a.l=!0,a.exports}var n={};t.m=e,t.c=n,t.i=function(e){return e},t.d=function(e,n,r){t.o(e,n)||Object.defineProperty(e,n,{configurable:!1,enumerable:!0,get:r})},t.n=function(e){var n=e&&e.__esModule?function(){return e.default}:function(){return e};return t.d(n,"a",n),n},t.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},t.p="",t(t.s="./client/src/bundles/bundle.js")}({"./client/lang/src/en.json":function(e,t){e.exports={"MFAWebAuthnRegister.BACK":"Back","MFAWebAuthnRegister.COMPLETEREGISTRATION":"Complete registration","MFAWebAuthnRegister.DESCRIPTION":"Contact your administrator if you require a security key. ","MFAWebAuthnRegister.FAILURE":"Something went wrong. Please re-insert your key and try again","MFAWebAuthnRegister.HELP":"How to use security keys.","MFAWebAuthnRegister.INSTRUCTION":"Insert security key and press {button}","MFAWebAuthnRegister.REGISTER":"Register key","MFAWebAuthnRegister.REGISTERING":"Registering","MFAWebAuthnRegister.RETRY":"Retry","MFAWebAuthnRegister.SUCCESS":"Key verified","MFAWebAuthnRegister.WAITING":"Waiting","MFAWebAuthnVerify.DESCRIPTION":"Use your security key to verify your identity.","MFAWebAuthnVerify.FAILURE":"Something went wrong, please re-insert your key and try again","MFAWebAuthnVerify.HELP":"How to use security keys.","MFAWebAuthnVerify.INSTRUCTION":"Please insert your security key and {button}.","MFAWebAuthnVerify.RETRY":"Try again","MFAWebAuthnVerify.SUCCESS":"Logging in...","MFAWebAuthnVerify.VERIFY":"activate it","MFAWebAuthnVerify.WAITING":"Waiting..."}},"./client/src/boot/index.js":function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{default:e}}var a=n("./client/src/boot/registerComponents.js"),s=r(a),i=n("./client/src/boot/registerReducers.js"),o=r(i);window.document.addEventListener("DOMContentLoaded",function(){(0,s.default)(),(0,o.default)()})},"./client/src/boot/registerComponents.js":function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{default:e}}Object.defineProperty(t,"__esModule",{value:!0});var a=n(0),s=r(a),i=n("./client/src/components/WebAuthn/Register.js"),o=r(i),u=n("./client/src/components/WebAuthn/Verify.js"),c=r(u);t.default=function(){s.default.component.registerMany({WebAuthnRegister:o.default,WebAuthnVerify:c.default})}},"./client/src/boot/registerReducers.js":function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{default:e}}Object.defineProperty(t,"__esModule",{value:!0});var a=n(0),s=r(a),i=n("./client/src/state/webauthnAvailableReducer.js"),o=r(i);t.default=function(){s.default.reducer.register("web-authnAvailability",o.default)}},"./client/src/bundles/bundle.js":function(e,t,n){"use strict";n("./client/src/boot/index.js")},"./client/src/components/Icons/ActivateToken.js":function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var r=n("./node_modules/react/index.js"),a=function(e){return e&&e.__esModule?e:{default:e}}(r);t.default=function(){return a.default.createElement("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 240 240"},a.default.createElement("defs",null,a.default.createElement("style",null,".a{fill:none;}.b{fill:#549ad3;}.c,.g{fill:#333a48;}.d{fill:#ffcf6e;}.e{clip-path:url(#a);}.f{fill:#d6e1ea;}.g{opacity:0.2;}.h{fill:url(#b);}.i{fill:#fff;}"),a.default.createElement("clipPath",{id:"a"},a.default.createElement("circle",{className:"a",cx:"120",cy:"120",r:"120"})),a.default.createElement("linearGradient",{id:"b",x1:"-26.14",y1:"68.86",x2:"-11.09",y2:"-38.22",gradientUnits:"userSpaceOnUse"},a.default.createElement("stop",{offset:"0.58",stopColor:"#333a48"}),a.default.createElement("stop",{offset:"0.59",stopColor:"#424a5c"}))),a.default.createElement("title",null,"U2F"),a.default.createElement("circle",{className:"b",cx:"120",cy:"120",r:"120"}),a.default.createElement("path",{className:"c",d:"M127.91,93.4a1.22,1.22,0,0,0,1.21,1.22h35.61a3.77,3.77,0,0,0,3.56-4V74.33a3.77,3.77,0,0,0-3.56-4H129.12a1.22,1.22,0,0,0-1.21,1.22Zm34.38-13.32A2.22,2.22,0,1,1,160,82.3,2.24,2.24,0,0,1,162.29,80.08Z"}),a.default.createElement("path",{className:"c",d:"M114.18,76.44h15.35a0,0,0,0,1,0,0v9.12a3,3,0,0,1-3,3h-9.35a3,3,0,0,1-3-3V76.44A0,0,0,0,1,114.18,76.44Z",transform:"translate(204.35 -39.35) rotate(90)"}),a.default.createElement("circle",{className:"d",cx:"146.94",cy:"82.77",r:"7.27"}),a.default.createElement("rect",{className:"d",x:"121.65",y:"82.3",width:"2.02",height:"10.5",transform:"translate(210.21 -35.11) rotate(90)"}),a.default.createElement("rect",{className:"d",x:"122.46",y:"79.87",width:"2.02",height:"8.88",transform:"translate(207.78 -39.15) rotate(90)"}),a.default.createElement("rect",{className:"d",x:"121.65",y:"72.2",width:"2.02",height:"10.5",transform:"translate(200.11 -45.21) rotate(90)"}),a.default.createElement("rect",{className:"d",x:"122.46",y:"76.24",width:"2.02",height:"8.88",transform:"translate(204.15 -42.78) rotate(90)"}),a.default.createElement("g",{className:"e"},a.default.createElement("rect",{className:"f",x:"-157.14",y:"54",width:"285",height:"192",rx:"10",ry:"10"}),a.default.createElement("rect",{className:"c",x:"-139.64",y:"70",width:"250",height:"97",rx:"2",ry:"2"}),a.default.createElement("rect",{className:"g",x:"-62.64",y:"175",width:"96",height:"62",rx:"3",ry:"3"}),a.default.createElement("rect",{className:"c",x:"-139.64",y:"54",width:"250",height:"5"}),a.default.createElement("path",{className:"h",d:"M-149.51,51.5a2.52,2.52,0,0,1-2.25-1.41l-30.14-62a2.49,2.49,0,0,1,.13-2.42,2.47,2.47,0,0,1,2.12-1.17h330a2.47,2.47,0,0,1,2.12,1.17,2.47,2.47,0,0,1,.13,2.42l-30.14,62a2.5,2.5,0,0,1-2.25,1.41Z"}),a.default.createElement("path",{className:"c",d:"M150.37-13h0L120.23,49H-149.51l-30.14-62h330m0-5h-330a5,5,0,0,0-4.49,7.19l30.13,62a5,5,0,0,0,4.5,2.81H120.23a5,5,0,0,0,4.5-2.81l30.14-62a5,5,0,0,0-4.5-7.19Z"})),a.default.createElement("path",{className:"i",d:"M159,107.75a5.47,5.47,0,0,1,1.83.32,5.64,5.64,0,0,1,3.76,5.37c0,2.26,0,4.51,0,6.77v18.2a.6.6,0,0,0,.61.6.57.57,0,0,0,.5-.29c.89-1.49,2.34-3.08,4.49-3.08a6,6,0,0,1,4.32,1.5,5.45,5.45,0,0,1,1.43,2.18,1.28,1.28,0,0,0,1.2.86,1.2,1.2,0,0,0,.67-.21,5.81,5.81,0,0,1,3.2-1,5.33,5.33,0,0,1,2.77.76,5.81,5.81,0,0,1,2.43,3,5,5,0,0,1,.28,1.19,1.05,1.05,0,0,0,1,.93,1.07,1.07,0,0,0,.43-.09,5.53,5.53,0,0,1,2.4-.55h.08a5.57,5.57,0,0,1,5.45,4.66,17.12,17.12,0,0,1,.07,2.89v7.1c0,3.09-2.59,29-18,29H161.34l-1.1,0a4,4,0,0,1-1.42-.21A4.63,4.63,0,0,1,157,186a6,6,0,0,1-.5-.71L137,153.54a4.89,4.89,0,0,1,3.92-7.27h.22a5,5,0,0,1,3.86,1.86,8.76,8.76,0,0,1,.79,1.22l2.55,4.42,1.72,3a1.72,1.72,0,0,0,1.52.89,1.77,1.77,0,0,0,1.81-1.74c0-.73,0-1.26,0-1.42V113.52a5.62,5.62,0,0,1,5.61-5.77m0-5h0a10.6,10.6,0,0,0-10.61,10.75v30.94a10.12,10.12,0,0,0-7.28-3.18h-.47a9.9,9.9,0,0,0-8,14.77l0,.06,0,.05,19.47,31.75a12.19,12.19,0,0,0,4.79,4.45,8.84,8.84,0,0,0,3.29.57h17.65c18.94,0,23-27.28,23-34v-7.1c0-.4,0-.73,0-1a12.7,12.7,0,0,0-.16-2.75,10.55,10.55,0,0,0-10.37-8.8H190a10.89,10.89,0,0,0-3.7-3.75A10.45,10.45,0,0,0,181,134a10.69,10.69,0,0,0-2.34.25,10.59,10.59,0,0,0-.74-.76,10.91,10.91,0,0,0-7.74-2.85h-.6V118c0-1.51,0-3,0-4.55a10.61,10.61,0,0,0-7.09-10.06,10.38,10.38,0,0,0-3.5-.6Z"}))}},"./client/src/components/Icons/CircleTick.js":function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var r=n("./node_modules/react/index.js"),a=function(e){return e&&e.__esModule?e:{default:e}}(r);t.default=function(e){var t=e.color,n=void 0===t?"currentColor":t,r=e.size,s=void 0===r?"3em":r;return a.default.createElement("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 512 512",height:s,width:s},a.default.createElement("g",{fill:n},a.default.createElement("path",{d:"M504 256c0 136.967-111.033 248-248 248S8 392.967 8 256 119.033 8 256 8s248 111.033 248 248zM227.314 387.314l184-184c6.248-6.248 6.248-16.379 0-22.627l-22.627-22.627c-6.248-6.249-16.379-6.249-22.628 0L216 308.118l-70.059-70.059c-6.248-6.248-16.379-6.248-22.628 0l-22.627 22.627c-6.248 6.248-6.248 16.379 0 22.627l104 104c6.249 6.249 16.379 6.249 22.628.001z"})))}},"./client/src/components/Icons/CircleWarning.js":function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var r=n("./node_modules/react/index.js"),a=function(e){return e&&e.__esModule?e:{default:e}}(r);t.default=function(e){var t=e.color,n=void 0===t?"currentColor":t,r=e.size,s=void 0===r?"3em":r;return a.default.createElement("svg",{width:s,height:s,viewBox:"0 0 80 80",xmlns:"http://www.w3.org/2000/svg"},a.default.createElement("g",{fill:n,fillRule:"nonzero"},a.default.createElement("path",{d:"M39.8233243,0 C17.9664349,0 0.272762495,17.8947368 0.272762495,40 C0.272762495,62.1052632 17.9664349,80 39.8233243,80 C61.6802137,80 79.3738861,62.1052632 79.3738861,40 C79.3738861,17.8947368 61.6802137,0 39.8233243,0 Z M44.5069435,62.6315789 C43.2926718,63.8596491 41.7314654,64.5614035 40.170259,64.5614035 C38.4355853,64.5614035 36.8743789,63.8596491 35.8335746,62.6315789 C34.619303,61.5789474 33.9254335,60 33.9254335,58.245614 C33.9254335,56.6666667 34.619303,55.0877193 35.8335746,53.8596491 C38.0886505,51.5789474 42.2518676,51.5789474 44.5069435,53.8596491 C45.7212151,55.0877193 46.2416172,56.6666667 46.2416172,58.245614 C46.4150846,60 45.7212151,61.5789474 44.5069435,62.6315789 Z M47.2824215,23.3333333 L45.0273456,44.0350877 C44.8538782,46.8421053 42.4253349,48.7719298 39.6498569,48.5964912 C37.2213136,48.245614 35.4866399,46.4912281 35.3131725,44.0350877 L33.0580966,23.3333333 C32.7111619,19.2982456 35.4866399,15.7894737 39.4763895,15.2631579 C43.4661392,14.9122807 46.9354867,17.8947368 47.2824215,21.9298246 C47.4558889,22.2807018 47.4558889,22.8070175 47.2824215,23.3333333 Z"})))}},"./client/src/components/LoadingIndicator.js":function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{default:e}}Object.defineProperty(t,"__esModule",{value:!0});var a=n("./node_modules/react/index.js"),s=r(a),i=n("./node_modules/classnames/index.js"),o=r(i);t.default=function(e){var t=e.block,n=void 0!==t&&t,r=e.size,a=void 0===r?"6em":r;return s.default.createElement("div",{style:{height:a,width:a},className:(0,o.default)({"mfa-loading-indicator":!0,"mfa-loading-indicator--block":n})})}},"./client/src/components/WebAuthn/Register.js":function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{default:e}}function a(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}function s(e,t){if(!e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!t||"object"!=typeof t&&"function"!=typeof t?e:t}function i(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function, not "+typeof t);e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,enumerable:!1,writable:!0,configurable:!0}}),t&&(Object.setPrototypeOf?Object.setPrototypeOf(e,t):e.__proto__=t)}Object.defineProperty(t,"__esModule",{value:!0}),t.Component=t.VIEWS=void 0;var o=function(){function e(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}return function(t,n,r){return n&&e(t.prototype,n),r&&e(t,r),t}}(),u=n("./node_modules/react/index.js"),c=r(u),l=n("./node_modules/prop-types/index.js"),f=r(l),d=n("./client/src/lib/auth.js"),p=n("./node_modules/classnames/index.js"),m=r(p),h=n("./client/src/components/Icons/CircleTick.js"),y=r(h),b=n("./client/src/components/Icons/CircleWarning.js"),g=r(b),A=n("./client/src/components/LoadingIndicator.js"),v=r(A),_=n("./client/src/components/Icons/ActivateToken.js"),E=r(_),R=n("./client/lang/src/en.json"),S=t.VIEWS={LOADING:"LOADING",READY:"READY",ERROR:"ERROR",PROMPTING:"PROMPTING",FAILURE:"FAILURE",SUCCESS:"SUCCESS"},j=function(e){function t(e){a(this,t);var n=s(this,(t.__proto__||Object.getPrototypeOf(t)).call(this,e)),r=S.LOADING;return e.keyData?r=S.READY:e.errors.length&&(r=S.ERROR),n.state={view:r,registrationData:null},n.handleBack=n.handleBack.bind(n),n.handleNext=n.handleNext.bind(n),n.handleStartRegistration=n.handleStartRegistration.bind(n),n}return i(t,e),o(t,[{key:"componentDidUpdate",value:function(){var e=this.props.keyData;this.state.view===S.LOADING&&e&&this.setState({view:S.READY})}},{key:"handleBack",value:function(){this.props.onBack()}},{key:"handleNext",value:function(){var e=this.state.registrationData;if(null===e)return void this.setState({view:S.FAILURE});this.props.onCompleteRegistration(e)}},{key:"handleStartRegistration",value:function(){var e=this;this.setState({view:S.PROMPTING}),(0,d.performRegistration)(this.props.keyData).then(function(t){return e.setState({view:S.SUCCESS,registrationData:t})}).catch(function(){return e.setState({view:S.FAILURE})})}},{key:"renderDescription",value:function(){var e=window,t=e.ss.i18n,n=this.props.method,r=n.supportLink,a=n.supportText,s=t._t("MFAWebAuthnRegister.REGISTER",R["MFAWebAuthnRegister.REGISTER"]),i=t.inject(t._t("MFAWebAuthnRegister.INSTRUCTION",R["MFAWebAuthnRegister.INSTRUCTION"]),{button:"<strong>"+s+"</strong>"});return c.default.createElement("div",{className:"mfa-registration-container__description"},c.default.createElement("p",null,t._t("MFAWebAuthnRegister.DESCRIPTION",R["MFAWebAuthnRegister.DESCRIPTION"]),r&&c.default.createElement("a",{href:r,target:"_blank",rel:"noopener noreferrer"},a||t._t("MFAWebAuthnRegister.HELP",R["MFAWebAuthnRegister.HELP"]))),c.default.createElement("p",{dangerouslySetInnerHTML:{__html:i}}))}},{key:"renderStatus",value:function(){var e=this.props.errors,t=window,n=t.ss.i18n;switch(this.state.view){case S.READY:return c.default.createElement("div",{className:"mfa-registration-container__status status-message--empty"});case S.PROMPTING:case S.LOADING:default:return c.default.createElement("div",{className:"mfa-registration-container__status status-message--loading"},c.default.createElement(v.default,{size:"3em"}),c.default.createElement("span",{className:"status-message__description"},n._t("MFAWebAuthnRegister.WAITING",R["MFAWebAuthnRegister.WAITING"])));case S.SUCCESS:return c.default.createElement("div",{className:"mfa-registration-container__status status-message--success"},c.default.createElement("span",{className:"status-message__icon"},c.default.createElement(y.default,{size:"32px"})),c.default.createElement("span",{className:"status-message__description"},n._t("MFAWebAuthnRegister.SUCCESS",R["MFAWebAuthnRegister.SUCCESS"])));case S.FAILURE:return c.default.createElement("div",{className:"mfa-registration-container__status status-message--failure"},c.default.createElement("span",{className:"status-message__icon"},c.default.createElement(g.default,{size:"32px"})),c.default.createElement("span",{className:"status-message__description"},n._t("MFAWebAuthnRegister.FAILURE",R["MFAWebAuthnRegister.FAILURE"])));case S.ERROR:return c.default.createElement("div",{className:"mfa-registration-container__status status-message--error"},c.default.createElement("span",{className:"status-message__icon"},c.default.createElement(g.default,{size:"32px"})),c.default.createElement("span",{className:"status-message__description"},e.join(", ")))}}},{key:"renderThumbnail",value:function(){return c.default.createElement("div",{className:"mfa-registration-container__thumbnail"},c.default.createElement(E.default,null))}},{key:"renderActions",value:function(){var e=window,t=e.ss.i18n,n=this.state.view,r=[];switch(n){case S.FAILURE:r=[{action:this.handleStartRegistration,name:t._t("MFAWebAuthnRegister.RETRY",R["MFAWebAuthnRegister.RETRY"])},{action:this.handleBack,name:t._t("MFAWebAuthnRegister.BACK",R["MFAWebAuthnRegister.BACK"])}];break;case S.ERROR:r=[];break;case S.READY:r=[{action:this.handleStartRegistration,name:t._t("MFAWebAuthnRegister.REGISTER",R["MFAWebAuthnRegister.REGISTER"])},{action:this.handleBack,name:t._t("MFAWebAuthnRegister.BACK",R["MFAWebAuthnRegister.BACK"])}];break;case S.PROMPTING:r=[{action:this.handleStartRegistration,name:t._t("MFAWebAuthnRegister.REGISTERING",R["MFAWebAuthnRegister.REGISTERING"]),disabled:!0},{action:this.handleBack,name:t._t("MFAWebAuthnRegister.BACK",R["MFAWebAuthnRegister.BACK"]),disabled:!0}];break;case S.LOADING:default:r=[{action:this.handleStartRegistration,name:t._t("MFAWebAuthnRegister.REGISTERING",R["MFAWebAuthnRegister.REGISTERING"]),disabled:!0},{action:this.handleBack,name:t._t("MFAWebAuthnRegister.BACK",R["MFAWebAuthnRegister.BACK"])}];break;case S.SUCCESS:r=[{action:this.handleNext,name:t._t("MFAWebAuthnRegister.COMPLETEREGISTRATION",R["MFAWebAuthnRegister.COMPLETEREGISTRATION"])}]}return c.default.createElement("div",{className:"mfa-registration-container__actions mfa-action-list"},r.map(function(e,t){var n=0===t,r=(0,m.default)("btn","mfa-action-list__item",{"btn-primary":n,"btn-secondary":!n});return c.default.createElement("button",{key:e.name,className:r,disabled:e.disabled||!1,onClick:e.action,type:"button"},e.name)}))}},{key:"render",value:function(){return c.default.createElement("div",{className:"mfa-registration-container mfa-registration-container--web-authn"},this.renderDescription(),this.renderStatus(),this.renderThumbnail(),this.renderActions())}}]),t}(u.Component);j.propTypes={keyData:f.default.object,method:f.default.object.isRequired,errors:f.default.arrayOf(f.default.string),onBack:f.default.func.isRequired,onCompleteRegistration:f.default.func.isRequired},j.defaultProps={errors:[]},j.displayName="WebAuthnRegister",t.Component=j,t.default=j},"./client/src/components/WebAuthn/Verify.js":function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{default:e}}function a(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}function s(e,t){if(!e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!t||"object"!=typeof t&&"function"!=typeof t?e:t}function i(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function, not "+typeof t);e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,enumerable:!1,writable:!0,configurable:!0}}),t&&(Object.setPrototypeOf?Object.setPrototypeOf(e,t):e.__proto__=t)}Object.defineProperty(t,"__esModule",{value:!0});var o=function(){function e(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}return function(t,n,r){return n&&e(t.prototype,n),r&&e(t,r),t}}(),u=n("./node_modules/react/index.js"),c=r(u),l=n("./node_modules/prop-types/index.js"),f=r(l),d=n("./client/src/types/publicKey.js"),p=r(d),m=n("./client/src/lib/auth.js"),h=n("./client/src/components/Icons/CircleTick.js"),y=r(h),b=n("./client/src/components/Icons/CircleWarning.js"),g=r(b),A=n("./client/src/components/LoadingIndicator.js"),v=r(A),_=n("./client/src/components/Icons/ActivateToken.js"),E=r(_),R=n("./client/lang/src/en.json"),S=function(e){function t(e){a(this,t);var n=s(this,(t.__proto__||Object.getPrototypeOf(t)).call(this,e));return n.state={failure:!1,success:!1},n.startAuth=n.startAuth.bind(n),n.handleRetry=n.handleRetry.bind(n),n}return i(t,e),o(t,[{key:"handleRetry",value:function(e){e.preventDefault(),this.setState({failure:!1})}},{key:"startAuth",value:function(){var e=this,t=this.props,n=t.publicKey,r=t.onCompleteVerification;(0,m.performVerification)(n).then(function(t){e.setState({success:!0},function(){return setTimeout(function(){r(t)},1e3)})}).catch(function(){return e.setState({failure:!0})})}},{key:"renderDescription",value:function(){var e=window,t=e.ss.i18n,n=this.props.method.supportLink,r=t._t("MFAWebAuthnVerify.VERIFY",R["MFAWebAuthnVerify.VERIFY"]),a=t.inject(t._t("MFAWebAuthnVerify.INSTRUCTION",R["MFAWebAuthnVerify.INSTRUCTION"]),{button:"<strong>"+r+"</strong>"});return c.default.createElement("div",{className:"mfa-verification-container__description"},c.default.createElement("p",null,t._t("MFAWebAuthnVerify.DESCRIPTION",R["MFAWebAuthnVerify.DESCRIPTION"]),n&&c.default.createElement("a",{href:n,target:"_blank",rel:"noopener noreferrer"},t._t("MFAWebAuthnVerify.HELP",R["MFAWebAuthnVerify.HELP"]))),c.default.createElement("p",{dangerouslySetInnerHTML:{__html:a}}))}},{key:"renderStatus",value:function(){var e=window,t=e.ss.i18n,n=this.props.errors,r=this.state,a=r.failure,s=r.success;return n.length?c.default.createElement("div",{className:"mfa-verification-container__status status-message--error"},c.default.createElement("span",{className:"status-message__icon"},c.default.createElement(g.default,{size:"32px"})),c.default.createElement("span",{className:"status-message__description"},n.join(", "))):s?c.default.createElement("div",{className:"mfa-verification-container__status status-message--success"},c.default.createElement("span",{className:"status-message__icon"},c.default.createElement(y.default,{size:"32px"})),c.default.createElement("span",{className:"status-message__description"},t._t("MFAWebAuthnVerify.SUCCESS",R["MFAWebAuthnVerify.SUCCESS"]))):a?c.default.createElement("div",{className:"mfa-verification-container__status status-message--failure"},c.default.createElement("span",{className:"status-message__icon"},c.default.createElement(g.default,{size:"32px"})),c.default.createElement("span",{className:"status-message__description"},t._t("MFAWebAuthnVerify.FAILURE",R["MFAWebAuthnVerify.FAILURE"]))):c.default.createElement("div",{className:"mfa-verification-container__status status-message--loading"},c.default.createElement(v.default,{size:"3em"}),c.default.createElement("span",{className:"status-message__description"},t._t("MFAWebAuthnVerify.WAITING",R["MFAWebAuthnVerify.WAITING"])))}},{key:"renderThumbnail",value:function(){return c.default.createElement("div",{className:"mfa-verification-container__thumbnail"},c.default.createElement(E.default,null))}},{key:"renderActions",value:function(){var e=window,t=e.ss.i18n,n=this.props.moreOptionsControl,r=this.state,a=r.failure;if(r.success)return c.default.createElement("div",{className:"mfa-verification-container__actions mfa-action-list"});var s=t._t("MFAWebAuthnVerify.RETRY",R["MFAWebAuthnVerify.RETRY"]),i=c.default.createElement("button",{key:s,className:"btn mfa-action-list__item btn-primary",disabled:!1,onClick:this.handleRetry,type:"button"},s);return c.default.createElement("div",{className:"mfa-verification-container__actions mfa-action-list"},a?i:null,n)}},{key:"render",value:function(){var e=this.state,t=e.failure,n=e.success;return t||n||this.startAuth(),c.default.createElement("div",{className:"mfa-verification-container mfa-verification-container--web-authn"},this.renderDescription(),this.renderStatus(),this.renderThumbnail(),this.renderActions())}}]),t}(u.Component);S.propTypes={method:f.default.object.isRequired,publicKey:p.default,onCompleteVerification:f.default.func.isRequired,moreOptionsControl:f.default.func,errors:f.default.arrayOf(f.default.string)},S.defaultProps={errors:[]},t.default=S},"./client/src/lib/auth.js":function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.performVerification=t.performRegistration=void 0;var r=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},a=n("./client/src/lib/convert.js");t.performRegistration=function(e){return new Promise(function(t,n){void 0!==e.user&&void 0!==e.challenge||n("keyData not provided");var s=r({},e.user,{id:(0,a.base64ToByteArray)(e.user.id)}),i=r({},e,{user:s,challenge:(0,a.base64ToByteArray)(e.challenge)});window.navigator.credentials.create({publicKey:i}).then(function(e){t({credentials:btoa(JSON.stringify({id:e.id,type:e.type,rawId:(0,a.byteArrayToBase64)(e.rawId),response:{clientDataJSON:(0,a.byteArrayToBase64)(e.response.clientDataJSON),attestationObject:(0,a.byteArrayToBase64)(e.response.attestationObject)}}))})}).catch(function(e){n(e.message)})})},t.performVerification=function(e){return new Promise(function(t,n){var s=r({},e,{challenge:(0,a.base64ToByteArray)(e.challenge),allowCredentials:e.allowCredentials.map(function(e){return r({},e,{id:(0,a.base64ToByteArray)(e.id)})})});navigator.credentials.get({publicKey:s}).then(function(e){t({credentials:btoa(JSON.stringify({id:e.id,type:e.type,rawId:(0,a.byteArrayToBase64)(e.rawId),response:{clientDataJSON:(0,a.byteArrayToBase64)(e.response.clientDataJSON),authenticatorData:(0,a.byteArrayToBase64)(e.response.authenticatorData),signature:(0,a.byteArrayToBase64)(e.response.signature),userHandle:e.response.userHandle?(0,a.byteArrayToBase64)(e.response.userHandle):null}}))})}).catch(function(e){n(e.message)})})}},"./client/src/lib/convert.js":function(e,t,n){"use strict";function r(e){if(Array.isArray(e)){for(var t=0,n=Array(e.length);t<e.length;t++)n[t]=e[t];return n}return Array.from(e)}Object.defineProperty(t,"__esModule",{value:!0}),t.base64ToByteArray=function(e){var t=atob(e.replace(/_/g,"/").replace(/-/g,"+"));return Uint8Array.from(t,function(e){return e.charCodeAt(0)})},t.byteArrayToBase64=function(e){var t=new Uint8Array(e);return btoa(String.fromCharCode.apply(String,r(t)))}},"./client/src/state/webauthnAvailableReducer.js":function(e,t,n){"use strict";function r(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},t=!0,n=null;return"https:"!==window.location.protocol?(t=!1,n=window.ss.i18n._t("WebAuthnReducer.NOT_ON_HTTPS","This method can only be used over HTTPS.")):void 0===window.AuthenticatorResponse&&(t=!1,n=window.ss.i18n._t("WebAuthnReducer.UNSUPPORTED_BROWSER","Security keys are not supported by this browser")),a({},e,t?{}:{isAvailable:t,unavailableMessage:n})}Object.defineProperty(t,"__esModule",{value:!0});var a=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e};t.default=r},"./client/src/types/publicKey.js":function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var r=n("./node_modules/prop-types/index.js"),a=function(e){return e&&e.__esModule?e:{default:e}}(r);t.default=a.default.shape({challenge:a.default.string.isRequired,rpId:a.default.string,userVerification:a.default.string,allowCredentials:a.default.arrayOf(a.default.shape({id:a.default.string.isRequired,type:a.default.string.isRequired,transports:a.default.arrayOf(a.default.string)})),extensions:a.default.Object,timeout:a.default.number})},"./node_modules/classnames/index.js":function(e,t,n){var r,a;!function(){"use strict";function n(){for(var e=[],t=0;t<arguments.length;t++){var r=arguments[t];if(r){var a=typeof r;if("string"===a||"number"===a)e.push(r);else if(Array.isArray(r)&&r.length){var i=n.apply(null,r);i&&e.push(i)}else if("object"===a)for(var o in r)s.call(r,o)&&r[o]&&e.push(o)}}return e.join(" ")}var s={}.hasOwnProperty;void 0!==e&&e.exports?(n.default=n,e.exports=n):(r=[],void 0!==(a=function(){return n}.apply(t,r))&&(e.exports=a))}()},"./node_modules/object-assign/index.js":function(e,t,n){"use strict";function r(e){if(null===e||void 0===e)throw new TypeError("Object.assign cannot be called with null or undefined");return Object(e)}var a=Object.getOwnPropertySymbols,s=Object.prototype.hasOwnProperty,i=Object.prototype.propertyIsEnumerable;e.exports=function(){try{if(!Object.assign)return!1;var e=new String("abc");if(e[5]="de","5"===Object.getOwnPropertyNames(e)[0])return!1;for(var t={},n=0;n<10;n++)t["_"+String.fromCharCode(n)]=n;if("0123456789"!==Object.getOwnPropertyNames(t).map(function(e){return t[e]}).join(""))return!1;var r={};return"abcdefghijklmnopqrst".split("").forEach(function(e){r[e]=e}),"abcdefghijklmnopqrst"===Object.keys(Object.assign({},r)).join("")}catch(e){return!1}}()?Object.assign:function(e,t){for(var n,o,u=r(e),c=1;c<arguments.length;c++){n=Object(arguments[c]);for(var l in n)s.call(n,l)&&(u[l]=n[l]);if(a){o=a(n);for(var f=0;f<o.length;f++)i.call(n,o[f])&&(u[o[f]]=n[o[f]])}}return u}},"./node_modules/prop-types/factoryWithThrowingShims.js":function(e,t,n){"use strict";function r(){}function a(){}var s=n("./node_modules/prop-types/lib/ReactPropTypesSecret.js");a.resetWarningCache=r,e.exports=function(){function e(e,t,n,r,a,i){if(i!==s){var o=new Error("Calling PropTypes validators directly is not supported by the `prop-types` package. Use PropTypes.checkPropTypes() to call them. Read more at http://fb.me/use-check-prop-types");throw o.name="Invariant Violation",o}}function t(){return e}e.isRequired=e;var n={array:e,bool:e,func:e,number:e,object:e,string:e,symbol:e,any:e,arrayOf:t,element:e,elementType:e,instanceOf:t,node:e,objectOf:t,oneOf:t,oneOfType:t,shape:t,exact:t,checkPropTypes:a,resetWarningCache:r};return n.PropTypes=n,n}},"./node_modules/prop-types/index.js":function(e,t,n){e.exports=n("./node_modules/prop-types/factoryWithThrowingShims.js")()},"./node_modules/prop-types/lib/ReactPropTypesSecret.js":function(e,t,n){"use strict";e.exports="SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED"},"./node_modules/react/cjs/react.production.min.js":function(e,t,n){"use strict";function r(e){for(var t="https://reactjs.org/docs/error-decoder.html?invariant="+e,n=1;n<arguments.length;n++)t+="&args[]="+encodeURIComponent(arguments[n]);return"Minified React error #"+e+"; visit "+t+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}function a(e,t,n){this.props=e,this.context=t,this.refs=F,this.updater=n||k}function s(){}function i(e,t,n){this.props=e,this.context=t,this.refs=F,this.updater=n||k}function o(e,t,n){var r,a={},s=null,i=null;if(null!=t)for(r in void 0!==t.ref&&(i=t.ref),void 0!==t.key&&(s=""+t.key),t)U.call(t,r)&&!V.hasOwnProperty(r)&&(a[r]=t[r]);var o=arguments.length-2;if(1===o)a.children=n;else if(1<o){for(var u=Array(o),c=0;c<o;c++)u[c]=arguments[c+2];a.children=u}if(e&&e.defaultProps)for(r in o=e.defaultProps)void 0===a[r]&&(a[r]=o[r]);return{$$typeof:E,type:e,key:s,ref:i,props:a,_owner:L.current}}function u(e,t){return{$$typeof:E,type:e.type,key:t,ref:e.ref,props:e.props,_owner:e._owner}}function c(e){return"object"==typeof e&&null!==e&&e.$$typeof===E}function l(e){var t={"=":"=0",":":"=2"};return"$"+(""+e).replace(/[=:]/g,function(e){return t[e]})}function f(e,t,n,r){if(B.length){var a=B.pop();return a.result=e,a.keyPrefix=t,a.func=n,a.context=r,a.count=0,a}return{result:e,keyPrefix:t,func:n,context:r,count:0}}function d(e){e.result=null,e.keyPrefix=null,e.func=null,e.context=null,e.count=0,10>B.length&&B.push(e)}function p(e,t,n,a){var s=typeof e;"undefined"!==s&&"boolean"!==s||(e=null);var i=!1;if(null===e)i=!0;else switch(s){case"string":case"number":i=!0;break;case"object":switch(e.$$typeof){case E:case R:i=!0}}if(i)return n(a,e,""===t?"."+h(e,0):t),1;if(i=0,t=""===t?".":t+":",Array.isArray(e))for(var o=0;o<e.length;o++){s=e[o];var u=t+h(s,o);i+=p(s,u,n,a)}else if(null===e||"object"!=typeof e?u=null:(u=W&&e[W]||e["@@iterator"],u="function"==typeof u?u:null),"function"==typeof u)for(e=u.call(e),o=0;!(s=e.next()).done;)s=s.value,u=t+h(s,o++),i+=p(s,u,n,a);else if("object"===s)throw n=""+e,Error(r(31,"[object Object]"===n?"object with keys {"+Object.keys(e).join(", ")+"}":n,""));return i}function m(e,t,n){return null==e?0:p(e,"",t,n)}function h(e,t){return"object"==typeof e&&null!==e&&null!=e.key?l(e.key):t.toString(36)}function y(e,t){e.func.call(e.context,t,e.count++)}function b(e,t,n){var r=e.result,a=e.keyPrefix;e=e.func.call(e.context,t,e.count++),Array.isArray(e)?g(e,r,n,function(e){return e}):null!=e&&(c(e)&&(e=u(e,a+(!e.key||t&&t.key===e.key?"":(""+e.key).replace(D,"$&/")+"/")+n)),r.push(e))}function g(e,t,n,r,a){var s="";null!=n&&(s=(""+n).replace(D,"$&/")+"/"),t=f(t,s,r,a),m(e,b,t),d(t)}function A(){var e=x.current;if(null===e)throw Error(r(321));return e}var v=n("./node_modules/object-assign/index.js"),_="function"==typeof Symbol&&Symbol.for,E=_?Symbol.for("react.element"):60103,R=_?Symbol.for("react.portal"):60106,S=_?Symbol.for("react.fragment"):60107,j=_?Symbol.for("react.strict_mode"):60108,w=_?Symbol.for("react.profiler"):60114,O=_?Symbol.for("react.provider"):60109,C=_?Symbol.for("react.context"):60110,I=_?Symbol.for("react.forward_ref"):60112,M=_?Symbol.for("react.suspense"):60113;_&&Symbol.for("react.suspense_list");var N=_?Symbol.for("react.memo"):60115,T=_?Symbol.for("react.lazy"):60116;_&&Symbol.for("react.fundamental"),_&&Symbol.for("react.responder"),_&&Symbol.for("react.scope");var W="function"==typeof Symbol&&Symbol.iterator,k={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},F={};a.prototype.isReactComponent={},a.prototype.setState=function(e,t){if("object"!=typeof e&&"function"!=typeof e&&null!=e)throw Error(r(85));this.updater.enqueueSetState(this,e,t,"setState")},a.prototype.forceUpdate=function(e){this.updater.enqueueForceUpdate(this,e,"forceUpdate")},s.prototype=a.prototype;var P=i.prototype=new s;P.constructor=i,v(P,a.prototype),P.isPureReactComponent=!0;var x={current:null},L={current:null},U=Object.prototype.hasOwnProperty,V={key:!0,ref:!0,__self:!0,__source:!0},D=/\/+/g,B=[],G={Children:{map:function(e,t,n){if(null==e)return e;var r=[];return g(e,r,null,t,n),r},forEach:function(e,t,n){if(null==e)return e;t=f(null,null,t,n),m(e,y,t),d(t)},count:function(e){return m(e,function(){return null},null)},toArray:function(e){var t=[];return g(e,t,null,function(e){return e}),t},only:function(e){if(!c(e))throw Error(r(143));return e}},createRef:function(){return{current:null}},Component:a,PureComponent:i,createContext:function(e,t){return void 0===t&&(t=null),e={$$typeof:C,_calculateChangedBits:t,_currentValue:e,_currentValue2:e,_threadCount:0,Provider:null,Consumer:null},e.Provider={$$typeof:O,_context:e},e.Consumer=e},forwardRef:function(e){return{$$typeof:I,render:e}},lazy:function(e){return{$$typeof:T,_ctor:e,_status:-1,_result:null}},memo:function(e,t){return{$$typeof:N,type:e,compare:void 0===t?null:t}},useCallback:function(e,t){return A().useCallback(e,t)},useContext:function(e,t){return A().useContext(e,t)},useEffect:function(e,t){return A().useEffect(e,t)},useImperativeHandle:function(e,t,n){return A().useImperativeHandle(e,t,n)},useDebugValue:function(){},useLayoutEffect:function(e,t){return A().useLayoutEffect(e,t)},useMemo:function(e,t){return A().useMemo(e,t)},useReducer:function(e,t,n){return A().useReducer(e,t,n)},useRef:function(e){return A().useRef(e)},useState:function(e){return A().useState(e)},Fragment:S,Profiler:w,StrictMode:j,Suspense:M,createElement:o,cloneElement:function(e,t,n){if(null===e||void 0===e)throw Error(r(267,e));var a=v({},e.props),s=e.key,i=e.ref,o=e._owner;if(null!=t){if(void 0!==t.ref&&(i=t.ref,o=L.current),void 0!==t.key&&(s=""+t.key),e.type&&e.type.defaultProps)var u=e.type.defaultProps;for(c in t)U.call(t,c)&&!V.hasOwnProperty(c)&&(a[c]=void 0===t[c]&&void 0!==u?u[c]:t[c])}var c=arguments.length-2;if(1===c)a.children=n;else if(1<c){u=Array(c);for(var l=0;l<c;l++)u[l]=arguments[l+2];a.children=u}return{$$typeof:E,type:e.type,key:s,ref:i,props:a,_owner:o}},createFactory:function(e){var t=o.bind(null,e);return t.type=e,t},isValidElement:c,version:"16.11.0",__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED:{ReactCurrentDispatcher:x,ReactCurrentBatchConfig:{suspense:null},ReactCurrentOwner:L,IsSomeRendererActing:{current:!1},assign:v}},H={default:G},$=H&&G||H;e.exports=$.default||$},"./node_modules/react/index.js":function(e,t,n){"use strict";e.exports=n("./node_modules/react/cjs/react.production.min.js")},0:function(e,t){e.exports=Injector}});