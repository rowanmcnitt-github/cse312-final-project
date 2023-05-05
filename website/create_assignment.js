const addQuestionBtn = document.querySelector('.add-question-btn');
const form = document.querySelector('#login-form');
let questionCount = 1;

addQuestionBtn.addEventListener('click', () => {
  questionCount++;

  const newQuestion = document.createElement('div');
  newQuestion.classList.add('question-container');
  newQuestion.innerHTML = `
    <h3><label for="question-${questionCount}">Question ${questionCount}</label></h3>
    <input type="text" id="question-${questionCount}" name="question-${questionCount}" /><br />
    <h3><label for="answer-${questionCount}_1">Answer 1 (correct answer)</label></h3>
    <input type="text" id="answer-${questionCount}_1" name="answer-${questionCount}_1" /><br />
    <h3><label for="answer-${questionCount}_2">Answer 2</label></h3>
    <input type="text" id="answer-${questionCount}_2" name="answer-${questionCount}_2" /><br />
    <h3><label for="answer-${questionCount}_3">Answer 3</label></h3>
    <input type="text" id="answer-${questionCount}_3" name="answer-${questionCount}_3" /><br />
  `;

  form.insertBefore(newQuestion, form.lastElementChild);
});
