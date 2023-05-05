document.addEventListener('DOMContentLoaded', () => {
  const joinButtons = document.querySelectorAll('.join-button');
  const enterButtons = document.querySelectorAll('.enter-button');
  //
  joinButtons.forEach(button => {
    button.addEventListener('click', () => {
      const classId = button.getAttribute('data-class-id');
      const xhr = new XMLHttpRequest();
      //
      console.log('clicked join button id: ' + classId)
      //
      xhr.open('POST', '/join-class');
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(JSON.stringify({ class_id: classId }));
      xhr.onreadystatechange = () => {
        if (xhr.readyState === XMLHttpRequest.DONE) {
          if (xhr.status === 200) {
            console.log('joined class succesfully')
            location.reload();
          } else {
            console.log('failed to join class')
          }
        }
      };
    });
  });
  enterButtons.forEach(button => {
    button.addEventListener('click', () => {
      const classId = button.getAttribute('data-class-id');
      console.log('attempting to enter class: ' + classId)
      window.location.href = `/class/${classId}`;
    });
  });
});