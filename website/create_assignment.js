let questionNumber = 1;
const addQuestionBtn = document.querySelector('.add-question-btn');
const main = document.querySelector('main');

addQuestionBtn.addEventListener('click', () => {
  questionNumber++;
  const questionContainer = document.createElement('div');
  questionContainer.classList.add('question-container');
  questionContainer.innerHTML = `
    <h2>Question ${questionNumber}:</h2>
    <label for="question${questionNumber}">Question:</label>
    <input type="text" id="question${questionNumber}" name="question${questionNumber}"><br><br>
    <label for="answer${questionNumber}_1">Answer 1:</label>
    <input type="text" id="answer${questionNumber}_1" name="answer${questionNumber}_1"><br><br>
    <label for="answer${questionNumber}_2">Answer 2:</label>
    <input type="text" id="answer${questionNumber}_2" name="answer${questionNumber}_2"><br><br>
    <label for="answer${questionNumber}_3">Answer 3:</label>
    <input type="text" id="answer${questionNumber}_3" name="answer${questionNumber}_3"><br><br>
    <label for="answer${questionNumber}_4">Answer 4:</label>
    <input type="text" id="answer${questionNumber}_4" name="answer${questionNumber}_4"><br><br>
  `;
  main.appendChild(questionContainer);
  main.appendChild(addQuestionBtn);
});
