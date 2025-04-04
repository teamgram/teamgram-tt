const { pathname, hostname, href } = window.location;

if (pathname.startsWith('/z')) {
  window.location.href = href.replace('/z', '/a');
}

if (
  (hostname === 'weba.teamgram.net' || hostname === 'webz.teamgram.net') && !localStorage.getItem('tt-global-state')
) {
  window.location.href = 'https://web.teamgram.net/a';
}
