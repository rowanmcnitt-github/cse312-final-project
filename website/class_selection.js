document.addEventListener("DOMContentLoaded", function() {
  const navLinks = document.querySelectorAll('.navigation a');
  const sections = document.querySelectorAll('section');

  navLinks.forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      const sectionId = this.getAttribute('href').substring(1); // get the id of the corresponding section
      sections.forEach(section => section.classList.remove('active'));
      navLinks.forEach(link => link.classList.remove('active'));

      const activeSection = document.getElementById(sectionId);
      activeSection.classList.add('active');
      this.classList.add('active');

      const classItems = activeSection.querySelectorAll('.class-item');
      classItems.forEach(classItem => classItem.classList.remove('hidden'));
    });
  });

  document.getElementById('browse-classes').classList.add('active');
  const classItems = document.querySelectorAll('#browse-classes .class-item');
  classItems.forEach(classItem => classItem.classList.remove('hidden'));
});
